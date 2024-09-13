package reapers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	endpoint_id "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/labelsfilter"
	nomad_api "github.com/hashicorp/nomad/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type allocationInfoMock struct {
	mock.Mock
}

func (p *allocationInfoMock) Info(allocID string, q *nomad_api.QueryOptions) (*nomad_api.Allocation, *nomad_api.QueryMeta, error) {
	args := p.Called(allocID, q)

	r0 := args.Get(0)
	if r0 == nil {
		return nil, args.Get(1).(*nomad_api.QueryMeta), args.Error(2)
	}

	return args.Get(0).(*nomad_api.Allocation), args.Get(1).(*nomad_api.QueryMeta), args.Error(2)
}

type eventStreamerMock struct {
	mock.Mock
}

func (p *eventStreamerMock) Stream(ctx context.Context, topics map[nomad_api.Topic][]string, index uint64, q *nomad_api.QueryOptions) (<-chan *nomad_api.Events, error) {
	args := p.Called(ctx, topics, index, q)
	return args.Get(0).(chan *nomad_api.Events), args.Error(1)
}

type endpointUpdaterMock struct {
	mock.Mock
}

func (p *endpointUpdaterMock) EndpointList() ([]*models.Endpoint, error) {
	args := p.Called()
	return args.Get(0).([]*models.Endpoint), args.Error(1)
}

func (p *endpointUpdaterMock) EndpointGet(id string) (*models.Endpoint, error) {
	args := p.Called(id)
	return args.Get(0).(*models.Endpoint), args.Error(1)
}

func (p *endpointUpdaterMock) EndpointPatch(id string, ep *models.EndpointChangeRequest) error {
	args := p.Called(id, ep)
	return args.Error(0)
}

func (p *endpointUpdaterMock) EndpointDelete(id string) error {
	args := p.Called(id)
	return args.Error(0)
}

func TestEndpointReconcileNoEndpoints(t *testing.T) {
	eum := new(endpointUpdaterMock)
	eum.On("EndpointList").Return([]*models.Endpoint{}, nil).Once()

	_, err := NewEndpointReaper(eum, nil, nil, "nodeID")
	assert.Nil(t, err)

	eum.AssertExpectations(t)
}

func TestEndpointReconcileOneEndpoints(t *testing.T) {
	labelsfilter.ParseLabelPrefixCfg([]string{"netreap:.*"}, "")

	endpointOne := &models.Endpoint{
		ID: 1,
		Status: &models.EndpointStatus{
			ExternalIdentifiers: &models.EndpointIdentifiers{
				CniAttachmentID: "containerID:eth0",
			},
			Labels: &models.LabelConfigurationStatus{
				SecurityRelevant: models.Labels{"reserved:init"},
			},
		},
	}
	allocationOne := &nomad_api.Allocation{
		ID:        "containerID",
		JobID:     "jobID",
		Namespace: "namespace",
		TaskGroup: "taskGroup",
		Job: &nomad_api.Job{
			Meta: map[string]string{},
		},
		NetworkStatus: &nomad_api.AllocNetworkStatus{
			InterfaceName: "eth0",
		},
	}

	eum := new(endpointUpdaterMock)
	eum.On("EndpointList").Return([]*models.Endpoint{endpointOne}, nil).Once()
	eum.On("EndpointPatch", endpoint_id.NewCiliumID(endpointOne.ID), mock.MatchedBy(func(req *models.EndpointChangeRequest) bool {
		assert.ElementsMatch(t, req.Labels, models.Labels{
			"netreap:nomad.job_id=jobID",
			"netreap:nomad.namespace=namespace",
			"netreap:nomad.task_group_id=taskGroup",
		})
		return true
	})).Return(nil).Once()

	aim := new(allocationInfoMock)
	aim.On("Info", "containerID", mock.MatchedBy(func(q *nomad_api.QueryOptions) bool {
		return q.Namespace == "*"
	})).Return(allocationOne, &nomad_api.QueryMeta{}, nil).Once()

	esm := new(eventStreamerMock)

	_, err := NewEndpointReaper(eum, aim, esm, "nodeID")
	assert.Nil(t, err)

	eum.AssertExpectations(t)
	aim.AssertExpectations(t)
	esm.AssertExpectations(t)
}

func TestEndpointReconcileOneEndpointToDelete(t *testing.T) {
	labelsfilter.ParseLabelPrefixCfg([]string{"netreap:.*"}, "")

	endpointOne := &models.Endpoint{
		ID: 1,
		Status: &models.EndpointStatus{
			ExternalIdentifiers: &models.EndpointIdentifiers{
				CniAttachmentID: "containerID:eth0",
			},
			Labels: &models.LabelConfigurationStatus{
				SecurityRelevant: models.Labels{
					"netreap:nomad.job_id=jobID",
					"netreap:nomad.namespace=namespace",
					"netreap:nomad.task_group_id=taskGroup",
				},
			},
		},
	}

	eum := new(endpointUpdaterMock)
	eum.On("EndpointList").Return([]*models.Endpoint{endpointOne}, nil).Once()
	eum.On("EndpointDelete", endpoint_id.NewCiliumID(endpointOne.ID)).Return(nil).Once()

	aim := new(allocationInfoMock)
	aim.On("Info", "containerID", mock.MatchedBy(func(q *nomad_api.QueryOptions) bool {
		return q.Namespace == "*"
	})).Return(nil, &nomad_api.QueryMeta{}, nil).Once()

	esm := new(eventStreamerMock)

	_, err := NewEndpointReaper(eum, aim, esm, "nodeID")
	assert.Nil(t, err)

	eum.AssertExpectations(t)
	aim.AssertExpectations(t)
	esm.AssertExpectations(t)
}

func TestEndpointRunErrorHandling(t *testing.T) {
	eum := new(endpointUpdaterMock)
	eum.On("EndpointList").Return([]*models.Endpoint{}, nil).Once()

	aim := new(allocationInfoMock)

	events := make(chan *nomad_api.Events, 3)

	esm := new(eventStreamerMock)
	esm.On("Stream", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {

		// One normal event
		events <- &nomad_api.Events{
			Index: 1,
			Err:   nil,
			Events: []nomad_api.Event{
				{
					Topic: nomad_api.TopicAllocation,
					Type:  "AllocationUpdated",
				},
			},
		}

		// Should exit at this point with the returned error
		events <- &nomad_api.Events{
			Index: 2,
			Err:   fmt.Errorf("fatal error"),
		}

		// This event will not be consumed as the routine should exit
		events <- &nomad_api.Events{
			Index: 3,
			Err:   nil,
			Events: []nomad_api.Event{
				{
					Topic: nomad_api.TopicAllocation,
					Type:  "AllocationUpdated",
				},
			},
		}

	}).Return(events, nil).Once()

	reaper, err := NewEndpointReaper(eum, aim, esm, "nodeID")
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	failChan, err := reaper.Run(ctx)
	assert.Nil(t, err, "unexpected error running endpoint reaper")

	event := <-events
	assert.NotNil(t, event, "expected left over event but got <nil>")

	fail := <-failChan
	assert.True(t, fail, "expected fail but got <false>")

	close(events)

}
