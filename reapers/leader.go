package reapers

import (
	"context"

	"github.com/cilium/cilium/pkg/kvstore"
	"go.uber.org/zap"

	"github.com/cosmonic-labs/netreap/elector"
)

type LeaderReaper struct {
	allocID       string
	ctx           context.Context
	kvStoreClient kvstore.BackendOperations
	nodeReaper    *NodeReaper
	idReaper      *IdentityReaper
}

// NewLeaderReaper creates a new LeaderReaper. This will run an initial reconciliation before returning the
// reaper
func NewLeaderReaper(ctx context.Context, kvStoreClient kvstore.BackendOperations, nomadNodeInfo NodeInfo, nomadEventStream EventStreamer, allocID string, clusterName string) (*LeaderReaper, error) {
	nodeReaper, err := NewNodeReaper(ctx, kvStoreClient, nomadNodeInfo, nomadEventStream, allocID, clusterName)
	if err != nil {
		return nil, err
	}

	idReaper, err := NewIdentityReaper(kvStoreClient)
	if err != nil {
		return nil, err
	}

	reaper := LeaderReaper{
		allocID:       allocID,
		ctx:           ctx,
		kvStoreClient: kvStoreClient,
		nodeReaper:    nodeReaper,
		idReaper:      idReaper,
	}

	return &reaper, nil
}

// Run the reaper until the context given in the contructor is cancelled. This function is non
// blocking and will only return errors if something occurs during startup
// return a channel to notify of nomad client failure
func (n *LeaderReaper) Run() (<-chan bool, error) {
	failChan := make(chan bool, 1)

	go func() {
		// Leader election
		election, err := elector.New(n.ctx, n.kvStoreClient, n.allocID)
		if err != nil {
			zap.L().Error("Unable to set up leader election", zap.Error(err))
			return
		}
		zap.L().Info("Waiting for leader election")
		<-election.SeizeThrone()
		zap.L().Info("Elected as leader, starting leader reapers")
		defer election.StepDown()

		zap.L().Info("Starting kvstore watchdog")
		go startKvstoreWatchdog()

		zap.L().Info("Starting identity gc")
		go n.idReaper.Run(n.ctx)

		zap.L().Info("Starting node reaper")
		nodeFailChan, err := n.nodeReaper.Run()
		if err != nil {
			zap.L().Error("Unable to start node reaper", zap.Error(err))
			failChan <- true
			return
		}

		for {
			select {
			case <-n.ctx.Done():
				zap.L().Info("Context cancelled, shutting down leader reapers")
				return
			case <-nodeFailChan:
				zap.S().Error("Node reaper kvstore client failed, shutting down")
				failChan <- true
				return
			}
		}
	}()

	return failChan, nil
}
