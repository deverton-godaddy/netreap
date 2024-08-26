package reapers

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	endpoint_id "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cosmonic-labs/netreap/internal/netreap"
	nomad_api "github.com/hashicorp/nomad/api"
	"go.uber.org/zap"

	backoff "github.com/cenkalti/backoff/v4"
)

type EndpointReaper struct {
	cilium           EndpointUpdater
	nomadAllocations AllocationInfo
	nomadEventStream EventStreamer
	nodeID           string
}

// NewEndpointReaper creates a new EndpointReaper. This will run an initial reconciliation before
// returning the reaper
func NewEndpointReaper(ciliumClient EndpointUpdater, nomadAllocations AllocationInfo, nomadEventStream EventStreamer, nodeID string) (*EndpointReaper, error) {
	reaper := EndpointReaper{
		cilium:           ciliumClient,
		nomadAllocations: nomadAllocations,
		nomadEventStream: nomadEventStream,
		nodeID:           nodeID,
	}

	// Do the initial reconciliation loop
	if err := reaper.reconcile(); err != nil {
		return nil, fmt.Errorf("unable to perform initial reconciliation: %s", err)
	}

	return &reaper, nil
}

// Run the reaper until the context given in the contructor is cancelled. This function is non
// blocking and will only return errors if something occurs during startup
// return a channel to notify of consul client failures
func (e *EndpointReaper) Run(ctx context.Context) (<-chan bool, error) {
	// NOTE: Specifying uint max so that it starts from the next available index. If there is a
	// better way to start from latest index, we can change this
	eventChan, err := e.nomadEventStream.Stream(
		ctx,
		map[nomad_api.Topic][]string{
			nomad_api.TopicAllocation: {"*"},
		},
		math.MaxInt64,
		&nomad_api.QueryOptions{
			Namespace: "*",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error when starting node event stream: %s", err)
	}

	failChan := make(chan bool, 1)

	go func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()

		for {
			select {
			case <-ctx.Done():
				zap.L().Info("Context cancelled, shutting down endpoint reaper")
				return

			case <-tick.C:
				zap.L().Info("Periodic reconciliation loop started")
				if err := e.reconcile(); err != nil {
					zap.L().Error("Error occurred during reconcilation, will retry next loop", zap.Error(err))
				}

			case events := <-eventChan:
				if events.Err != nil {
					zap.L().Error("Received error from Nomad event stream, exiting", zap.Error(events.Err))
					failChan <- true
					return
				}

				zap.L().Debug("Got events from Allocation topic. Handling...", zap.Int("event-count", len(events.Events)))

				for _, event := range events.Events {
					switch event.Type {
					case "AllocationUpdated":
						go e.handleAllocationUpdated(event)
					default:
						zap.L().Debug("Ignoring unhandled event from Allocation topic", zap.String("event-type", event.Type))
						continue
					}
				}
			}
		}
	}()

	return failChan, nil
}

func (e *EndpointReaper) reconcile() error {
	zap.L().Debug("Starting reconciliation")

	// Get current endpoints list
	endpoints, err := e.cilium.EndpointList()
	if err != nil {
		return fmt.Errorf("unable to list current cilium endpoints: %s", err)
	}

	zap.L().Debug("checking each endpoint", zap.Int("endpoints-total", len(endpoints)))

	for _, endpoint := range endpoints {
		containerID := endpoint.Status.ExternalIdentifiers.ContainerID

		// Only managing endpoints with container IDs
		if containerID == "" {
			zap.L().Debug("Skipping endpoint that is not associated with a container",
				zap.Int64("endpoint-id", endpoint.ID),
			)
			continue
		}

		// Nomad calls the CNI plugin with the allocation ID as the container ID
		allocation, _, err := e.nomadAllocations.Info(containerID, &nomad_api.QueryOptions{Namespace: "*"})
		if err != nil {
			return err
		}
		if allocation == nil {
			zap.L().Warn("Allocation not found in Nomad, removing endpoint",
				zap.String("container-id", containerID),
				zap.Int64("endpoint-id", endpoint.ID),
			)
			e.cilium.EndpointDelete(endpoint_id.NewCiliumID(endpoint.ID))
		} else {
			e.labelEndpoint(endpoint, allocation)
		}
	}

	zap.L().Debug("Finished reconciliation")

	return nil
}

func (e *EndpointReaper) handleAllocationUpdated(event nomad_api.Event) {
	allocation, err := event.Allocation()
	if err != nil {
		zap.L().Debug("Unable to deserialize Allocation",
			zap.String("event-type", event.Type),
			zap.Uint64("event-index", event.Index),
		)
		return
	}

	if allocation == nil {
		zap.L().Debug("Allocation was empty",
			zap.String("event-type", event.Type),
			zap.Uint64("event-index", event.Index),
		)
		return
	}

	if allocation.NodeID != e.nodeID {
		zap.L().Debug("Allocation is not for this node, ignoring",
			zap.String("event-type", event.Type),
			zap.Uint64("event-index", event.Index),
			zap.String("allocation-node-id", allocation.NodeID),
			zap.String("container-id", allocation.ID),
			zap.String("node-id", e.nodeID),
		)
		return
	}

	if allocation.NetworkStatus == nil || allocation.NetworkStatus.Address == "" {
		zap.L().Debug("Allocation has no IP address, ignoring",
			zap.String("event-type", event.Type),
			zap.Uint64("event-index", event.Index),
			zap.String("container-id", allocation.ID),
		)
		return
	}

	if allocation.ServerTerminalStatus() || allocation.ClientTerminalStatus() {
		zap.L().Debug("Allocation is terminating, ignoring",
			zap.String("event-type", event.Type),
			zap.Uint64("event-index", event.Index),
			zap.String("container-id", allocation.ID),
			zap.String("client-status", allocation.ClientStatus),
			zap.String("desired-status", allocation.DesiredStatus),
		)
		return
	}

	endpoint, err := e.cilium.EndpointGet(endpoint_id.NewCNIAttachmentID(allocation.ID, allocation.NetworkStatus.InterfaceName))
	if err != nil {
		fields := []zap.Field{zap.String("event-type", event.Type),
			zap.Uint64("event-index", event.Index),
			zap.String("container-id", allocation.ID),
			zap.Error(err),
		}
		if endpoint != nil {
			fields = append(fields, zap.Int64("endpoint-id", endpoint.ID))
		}
		if strings.Contains(err.Error(), "getEndpointIdNotFound") {
			// This is fine, the endpoint probably just isn't on this host
			zap.L().Debug("Endpoint not found", fields...)
		} else {
			zap.L().Warn("Unable to get endpoint", fields...)
		}
		return
	}

	if allocation.Job == nil {
		// Fetch the full allocation since the event didn't have the Job with the metadata
		allocation, _, err = e.nomadAllocations.Info(allocation.ID, &nomad_api.QueryOptions{Namespace: allocation.Namespace})
		if err != nil {
			zap.L().Warn("Couldn't fetch allocation from Nomad",
				zap.String("event-type", event.Type),
				zap.Uint64("event-index", event.Index),
				zap.String("container-id", allocation.ID),
				zap.Int64("endpoint-id", endpoint.ID),
				zap.Error(err),
			)
			return
		}
	}

	e.labelEndpoint(endpoint, allocation)
}

func (e *EndpointReaper) labelEndpoint(endpoint *models.Endpoint, allocation *nomad_api.Allocation) {
	metadata := map[string]string{
		fmt.Sprintf("%s:%s", netreap.LabelSourceNetreap, netreap.LabelKeyNomadJobID):       allocation.JobID,
		fmt.Sprintf("%s:%s", netreap.LabelSourceNetreap, netreap.LabelKeyNomadNamespace):   allocation.Namespace,
		fmt.Sprintf("%s:%s", netreap.LabelSourceNetreap, netreap.LabelKeyNomadTaskGroupID): allocation.TaskGroup,
	}

	// Combine the metadata from the job and the task group with the task group taking precedence
	for k, v := range allocation.Job.Meta {
		metadata[fmt.Sprintf("%s:%s", netreap.LabelSourceNomad, k)] = v
	}

	for _, taskGroup := range allocation.Job.TaskGroups {
		if *taskGroup.Name == allocation.TaskGroup {
			for k, v := range taskGroup.Meta {
				metadata[fmt.Sprintf("%s:%s", netreap.LabelSourceNomad, k)] = v
			}
		}
	}

	// Split labels in to security identifiers and information labels
	newLabels := labels.Map2Labels(metadata, "")
	newIdLabels, _ := labelsfilter.Filter(newLabels)

	oldIdLabels := labels.NewLabelsFromModel(endpoint.Status.Labels.SecurityRelevant)

	// We only patch the endpoint if the security identity labels have changed
	if oldIdLabels.Equals(newIdLabels) {
		zap.L().Debug("Skipping endpoint as no security identity labels have changed",
			zap.String("container-id", allocation.ID),
			zap.Int64("endpoint-id", endpoint.ID),
			zap.Strings("new-id-labels", newIdLabels.GetPrintableModel()),
			zap.Strings("old-id-labels", oldIdLabels.GetPrintableModel()),
		)
		return
	}

	zap.L().Info("Patching labels on endpoint",
		zap.String("container-id", allocation.ID),
		zap.Int64("endpoint-id", endpoint.ID),
		zap.Strings("new-id-labels", newIdLabels.GetPrintableModel()),
	)

	ecr := &models.EndpointChangeRequest{
		ContainerID:              allocation.ID,
		ContainerName:            allocation.Name,
		Labels:                   newLabels.GetModel(),
		State:                    models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		DisableLegacyIdentifiers: true,
		K8sPodName:               allocation.Name,
		K8sNamespace:             allocation.Namespace,
	}

	f := func() error {
		err := e.cilium.EndpointPatch(endpoint_id.NewCiliumID(endpoint.ID), ecr)
		if err != nil {
			// The Cilium client endpoints pass errors through Hint() that does fmt.Errorf to all errors without wrapping
			// so we have to treat them as strings
			if strings.Contains(err.Error(), "patchEndpointIdTooManyRequests") {
				zap.L().Warn("Hit Cilium API rate limit, retrying",
					zap.String("container-id", allocation.ID),
					zap.Int64("endpoint-id", endpoint.ID),
					zap.Strings("labels", newLabels.GetPrintableModel()),
				)
				return err
			}

			return &backoff.PermanentError{
				Err: err,
			}
		}
		return nil
	}

	err := backoff.Retry(f, backoff.NewExponentialBackOff())
	if err != nil {
		if permanent, ok := err.(*backoff.PermanentError); ok {
			zap.L().Error("Error while patching the endpoint labels of container",
				zap.String("container-id", allocation.ID),
				zap.Int64("endpoint-id", endpoint.ID),
				zap.Strings("labels", newLabels.GetPrintableModel()),
				zap.Error(permanent.Unwrap()),
			)
		}
	}

}
