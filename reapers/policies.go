package reapers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cosmonic-labs/netreap/internal/netreap"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"go.uber.org/zap"
)

const (

	// PoliciesKeyPrefix is prefix in the kvstore for policies
	PoliciesKeyPrefix = "netreap/policies/v1"

	// watcherChanSize is the size of the channel to buffer kvstore events
	watcherChanSize = 100
)

type PoliciesReaper struct {
	cilium        PolicyUpdater
	kvStoreClient kvstore.BackendOperations
	prefix        string
}

func init() {
	// Initialize LRU here because the policy processing
	// will call down to sanitizing the FQDN rules which contains regexes.
	// Regexes need to be compiled as part of the FQDN rule validation.
	re.InitRegexCompileLRU(1000)
}

func NewPoliciesReaper(kvStoreClient kvstore.BackendOperations, prefix string, cilium PolicyUpdater) (*PoliciesReaper, error) {
	return &PoliciesReaper{
		cilium:        cilium,
		kvStoreClient: kvStoreClient,
		prefix:        prefix,
	}, nil
}

func (p *PoliciesReaper) Run(ctx context.Context, concurrency int) (<-chan bool, error) {
	zap.L().Info("Keeping agent policy state in sync with kvstore")

	failChan := make(chan bool, 1)

	go func() {
		watcher := p.kvStoreClient.ListAndWatch(ctx, p.prefix, watcherChanSize)

		zap.L().Info("Synchronizing agent policy state with kvstore")

		err := p.reconcile(ctx, watcher, concurrency)
		if err != nil {
			zap.L().Error("Unable to reconcile initial policies", zap.Error(err))
			failChan <- true
			return
		}

		for {
			select {
			case <-ctx.Done():
				zap.L().Info("Context cancelled, shutting down policies reaper")
				return

			case event := <-watcher.Events:
				logger := zap.L().With(
					zap.String("event-key", event.Key),
					zap.String("event-type", event.Typ.String()),
				)

				keyName := strings.TrimPrefix(event.Key, p.prefix)
				if keyName[0] == '/' {
					keyName = keyName[1:]
				}

				err := p.handlePolicyEvent(logger, keyName, event)
				if err != nil {
					logger.Error("Unable to handle policy event", zap.ByteString("event-value", event.Value), zap.Error(err))
					failChan <- true
					return
				}
			}
		}
	}()

	return failChan, nil
}

func (p *PoliciesReaper) reconcile(ctx context.Context, watcher *kvstore.Watcher, concurrency int) error {
	oldPolicies, err := p.getCurrentPolicies()
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	for listDone := false; !listDone; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-watcher.Events:
			logger := zap.L().With(
				zap.String("event-key", event.Key),
				zap.String("event-type", event.Typ.String()),
			)

			switch event.Typ {

			case kvstore.EventTypeCreate:
				e := event

				keyName := strings.TrimPrefix(event.Key, p.prefix)
				if keyName[0] == '/' {
					keyName = keyName[1:]
				}

				labels := getIdentityLabels(keyName)

				oldPolicy, ok := oldPolicies[keyName]
				if ok {
					delete(oldPolicies, keyName)
				}

				g.Go(func() error {
					err := p.reconcilePolicy(logger, labels, oldPolicy, e)
					if err != nil {
						logger.Error("Unable to handle policy event", zap.ByteString("event-value", e.Value), zap.Error(err))
						return err
					}
					return nil
				})

			case kvstore.EventTypeModify:
				return fmt.Errorf("Received modify event during initial kvstore sync, this should never happen")

			case kvstore.EventTypeDelete:
				return fmt.Errorf("Received delete event during initial kvstore sync, this should never happen")

			case kvstore.EventTypeListDone:
				logger.Info("Initial policies sync complete")
				listDone = true

			default:
				return fmt.Errorf("Unhandled sync event type: %+v", event)
			}
		}
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// Anything left in the initial state map wasn't in the kvstore so should be deleted
	for oldKeyName := range oldPolicies {
		labels := getIdentityLabels(oldKeyName)

		zap.L().Debug("Deleting local policy not found in kvstore", zap.Strings("labels", labels.GetModel()))

		_, err := p.cilium.PolicyDelete(labels.GetModel())
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *PoliciesReaper) reconcilePolicy(logger *zap.Logger, labels labels.LabelArray, oldRules api.Rules, event kvstore.KeyValueEvent) error {
	newRules, err := parseRules(labels, event.Value)
	if err != nil {
		return err
	}

	if oldRules.DeepEqual(newRules) {
		logger.Debug("Skipping unchanged policy", zap.Strings("labels", labels.GetModel()))
		return nil
	}

	logger.Debug("Creating policy", zap.Strings("labels", labels.GetModel()))

	rulesValue, err := json.Marshal(newRules)
	if err != nil {
		return err
	}

	_, err = p.cilium.PolicyReplace(string(rulesValue), true, labels.GetModel())
	if err != nil {
		return err
	}

	return nil
}

func (p *PoliciesReaper) handlePolicyEvent(logger *zap.Logger, keyName string, event kvstore.KeyValueEvent) error {
	labels := getIdentityLabels(keyName)

	if event.Typ == kvstore.EventTypeDelete {
		logger.Debug("Deleting policy", zap.Strings("labels", labels.GetModel()))

		_, err := p.cilium.PolicyDelete(labels.GetModel())
		if err != nil {
			return err
		}

		return nil
	}

	newRules, err := parseRules(labels, event.Value)
	if err != nil {
		return err
	}

	newRulesValue, err := json.Marshal(newRules)
	if err != nil {
		return err
	}

	if event.Typ == kvstore.EventTypeCreate {
		logger.Debug("Creating policy", zap.Strings("labels", labels.GetModel()))

		_, err = p.cilium.PolicyReplace(string(newRulesValue), false, nil)
		if err != nil {
			return err
		}

		return nil
	} else if event.Typ == kvstore.EventTypeModify {
		oldPolicy, err := p.cilium.PolicyGet(labels.GetModel())
		if err != nil {
			return err
		}

		oldRules := api.Rules{}
		err = json.Unmarshal([]byte(oldPolicy.Policy), &oldRules)
		if err != nil {
			return err
		}

		if oldRules.DeepEqual(newRules) {
			logger.Debug("Ignoring unchanged policy", zap.Strings("labels", labels.GetModel()))
			return nil
		}

		logger.Debug("Replacing policy", zap.Strings("labels", labels.GetModel()))

		_, err = p.cilium.PolicyReplace(string(newRulesValue), false, labels.GetModel())
		if err != nil {
			return err
		}

		return nil
	}

	return nil
}

func (p *PoliciesReaper) getCurrentPolicies() (map[string]api.Rules, error) {
	agentPolicy, err := p.cilium.PolicyGet(nil)
	if err != nil {
		return nil, err
	}

	rules := api.Rules{}
	err = json.Unmarshal([]byte(agentPolicy.Policy), &rules)
	if err != nil {
		return nil, err
	}

	// Group rules by policy name
	rulesByName := make(map[string]api.Rules)
	for _, rule := range rules {

		// the call to Sanitize() is necessary to ensure that the policy is in a valid state as the JSON doesn't fully encode the policy
		if err := rule.Sanitize(); err != nil {
			return nil, fmt.Errorf("unable to sanitize network policy: %w", err)
		}

		policyName := rule.Labels.Get(netreap.LabelSourceNetreapKeyPrefix + netreap.LabelKeyCiliumPolicyName)
		rulesByName[policyName] = append(rulesByName[policyName], rule)
	}

	return rulesByName, nil
}

func parseRules(policyLabels labels.LabelArray, value []byte) (*api.Rules, error) {
	rules := api.Rules{}

	err := json.Unmarshal(value, &rules)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse network policy: %w", err)
	}

	for _, rule := range rules {
		if err := rule.Sanitize(); err != nil {
			return nil, fmt.Errorf("Unable to sanitize network policy: %w", err)
		}

		rule.Labels = append(policyLabels, rule.Labels...).Sort()
	}

	return &rules, nil
}

func getIdentityLabels(name string) labels.LabelArray {
	// Keep labels sorted by the key.
	return labels.LabelArray{
		labels.NewLabel(netreap.LabelKeyCiliumPolicyName, name, netreap.LabelSourceNetreap),
	}
}
