package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	cilium_client "github.com/cilium/cilium/pkg/client"
	cilium_command "github.com/cilium/cilium/pkg/command"
	cilium_kvstore "github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labelsfilter"
	cilium_logging "github.com/cilium/cilium/pkg/logging"
	nomad_api "github.com/hashicorp/nomad/api"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/cosmonic-labs/netreap/internal/zaplogrus"
	"github.com/cosmonic-labs/netreap/reapers"
)

var Version = "unreleased"

type config struct {
	clusterName     string
	debug           bool
	kvStore         string
	kvStoreOpts     map[string]string
	labels          *cli.StringSlice
	labelPrefixFile string
	policiesPrefix  string
}

func main() {
	ctx := context.Background()

	conf := config{}
	app := &cli.App{
		Name:  "netreap",
		Usage: "A custom monitor and reaper for cleaning up Cilium endpoints and nodes",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "debug",
				Value:       false,
				Usage:       "Enable debug logging",
				EnvVars:     []string{"NETREAP_DEBUG"},
				Destination: &conf.debug,
			},
			&cli.StringFlag{
				Name:        "policies-prefix",
				Aliases:     []string{"p"},
				Value:       reapers.PoliciesKeyPrefix,
				Usage:       "kvstore key prefix to watch for Cilium policy updates.",
				EnvVars:     []string{"NETREAP_POLICIES_PREFIX"},
				Destination: &conf.policiesPrefix,
			},
			&cli.StringFlag{
				Name:        "kvstore",
				Usage:       "Consul key to watch for Cilium policy updates.",
				EnvVars:     []string{"NETREAP_KVSTORE"},
				Destination: &conf.kvStore,
			},
			&cli.StringFlag{
				Name:    "kvstore-opts",
				Usage:   "Consul key to watch for Cilium policy updates.",
				EnvVars: []string{"NETREAP_KVSTORE_OPTS"},
			},
			&cli.StringFlag{
				Name:        "cluster-name",
				Usage:       "Cilium cluster name.",
				EnvVars:     []string{"NETREAP_CLUSTER_NAME"},
				Destination: &conf.clusterName,
			},
			&cli.StringSliceFlag{
				Name:        "labels",
				Usage:       "List of label prefixes used to determine identity of an endpoint.",
				Destination: conf.labels,
			},
			&cli.StringFlag{
				Name:        "label-prefix-file",
				Usage:       "Valid label prefixes file path.",
				Destination: &conf.labelPrefixFile,
			},
		},
		Before: func(ctx *cli.Context) error {
			// Borrow the parser from Cilium
			kvStoreOpt := ctx.String("kvstore-opts")
			if m, err := cilium_command.ToStringMapStringE(kvStoreOpt); err != nil {
				return fmt.Errorf("unable to parse %s: %w", kvStoreOpt, err)
			} else {
				conf.kvStoreOpts = m
			}

			return nil
		},
		Action: func(c *cli.Context) error {
			return run(c.Context, conf)
		},
		Version: Version,
	}

	if err := app.RunContext(ctx, os.Args); err != nil {
		zap.L().Fatal("Error running netreap", zap.Error(err))
	}
}

func configureLogging(debug bool) (logger *zap.Logger, err error) {
	// Step 0: Setup logging

	if debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	if err != nil {
		return nil, err
	}

	zap.ReplaceGlobals(logger)

	// Bridge Cilium logrus to netreap zap
	cilium_logging.DefaultLogger.SetReportCaller(true)
	cilium_logging.DefaultLogger.SetOutput(io.Discard)
	cilium_logging.DefaultLogger.AddHook(zaplogrus.NewZapLogrusHook(logger))

	return logger, nil
}

func run(ctx context.Context, conf config) error {

	logger, err := configureLogging(conf.debug)
	if err != nil {
		return fmt.Errorf("can't initialize zap logger: %w", err)
	}
	defer logger.Sync()

	if err := labelsfilter.ParseLabelPrefixCfg(conf.labels.Value(), conf.labelPrefixFile); err != nil {
		return fmt.Errorf("unable to parse Label prefix configuration: %w", err)
	}

	// Step 0: Construct the clients

	// Looks for the default Cilium socket path or uses the value from CILIUM_SOCK
	cilium_client, err := cilium_client.NewDefaultClient()
	if err != nil {
		return fmt.Errorf("error when connecting to cilium agent: %w", err)
	}

	// Fetch config from Cilium if not set
	resp, err := cilium_client.ConfigGet()
	if err != nil {
		return fmt.Errorf("unable to retrieve cilium configuration: %w", err)
	}
	if resp.Status == nil {
		return fmt.Errorf("unable to retrieve cilium configuration: empty response")
	}

	kvstoreConfig := resp.Status.KvstoreConfiguration

	if conf.kvStore == "" {
		conf.kvStore = kvstoreConfig.Type
	}

	if len(conf.kvStoreOpts) == 0 {
		for k, v := range kvstoreConfig.Options {
			conf.kvStoreOpts[k] = v
		}
	}

	if conf.clusterName == "" {
		conf.clusterName = resp.Status.DaemonConfigurationMap["ClusterName"].(string)
	}

	err = cilium_kvstore.Setup(ctx, conf.kvStore, conf.kvStoreOpts, nil)
	if err != nil {
		return fmt.Errorf("unable to connect to Cilium kvstore: %w", err)
	}

	// DefaultConfig fetches configuration data from well-known nomad variables (e.g. NOMAD_ADDR,
	// NOMAD_CACERT), so we'll just leverage that for now.
	nomad_client, err := nomad_api.NewClient(nomad_api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("unable to connect to Nomad: %w", err)
	}

	// Get the node ID of the instance we're running on
	self, err := nomad_client.Agent().Self()
	if err != nil {
		return fmt.Errorf("unable to query local agent info: %w", err)
	}

	clientStats, ok := self.Stats["client"]
	if !ok {
		return fmt.Errorf("not running on a client node")
	}

	nodeID, ok := clientStats["node_id"]
	if !ok {
		return fmt.Errorf("unable to get local node ID")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Step 1: Leader election
	zap.L().Debug("Starting leader reaper")
	nodeReaper, err := reapers.NewLeaderReaper(ctx, cilium_kvstore.Client(), nomad_client.Nodes(), nomad_client.EventStream(), os.Getenv("NOMAD_ALLOC_ID"), conf.clusterName)
	if err != nil {
		return err
	}

	leaderFailChan, err := nodeReaper.Run()
	if err != nil {
		return fmt.Errorf("unable to start leader reaper: %w", err)
	}

	// Step 2: Start the reapers
	zap.L().Debug("Starting endpoint reaper")
	endpoint_reaper, err := reapers.NewEndpointReaper(cilium_client, nomad_client.Allocations(), nomad_client.EventStream(), nodeID)
	if err != nil {
		return err
	}

	endpointFailChan, err := endpoint_reaper.Run(ctx)
	if err != nil {
		return fmt.Errorf("unable to start endpoint reaper: %w", err)
	}

	zap.S().Debug("Starting policies reaper")
	policiesReaper, err := reapers.NewPoliciesReaper(cilium_kvstore.Client(), conf.policiesPrefix, cilium_client)
	if err != nil {
		return err
	}

	policiesFailChan, err := policiesReaper.Run(ctx)
	if err != nil {
		return fmt.Errorf("unable to start policies reaper: %w", err)
	}

	// Wait for interrupt or client failure
	select {
	case <-c:
		zap.S().Info("Received interrupt, shutting down")
		cancel()
	case <-leaderFailChan:
		zap.S().Error("leader reaper kvstore client failed, shutting down")
		cancel()
	case <-endpointFailChan:
		zap.S().Error("endpoint reaper kvstore client failed, shutting down")
		cancel()
	case <-policiesFailChan:
		zap.S().Error("policies reaper kvstore client failed, shutting down")
		cancel()
	}

	return nil
}
