package reapers

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/defaults"
	ciliumIdentity "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/rate"
	"go.uber.org/zap"
)

type IdentityReaper struct {
	gcInterval     time.Duration
	gcRateInterval time.Duration
	gcRateLimit    int64

	// rateLimiter is meant to rate limit the number of
	// identities being GCed by the operator. See the documentation of
	// rate.Limiter to understand its difference than 'x/time/rate.Limiter'.
	//
	// With our rate.Limiter implementation Cilium will be able to handle bursts
	// of identities being garbage collected with the help of the functionality
	// provided by the 'policy-trigger-interval' in the cilium-agent. With the
	// policy-trigger even if we receive N identity changes over the interval
	// set, Cilium will only need to process all of them at once instead of
	// processing each one individually.
	rateLimiter *rate.Limiter

	allocator *allocator.Allocator
}

func NewIdentityReaper(kvStoreClient kvstore.BackendOperations) (*IdentityReaper, error) {
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil, kvStoreClient)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize kvstore backend for identity allocation")
	}

	minID := idpool.ID(ciliumIdentity.GetMinimalAllocationIdentity())
	maxID := idpool.ID(ciliumIdentity.GetMaximumAllocationIdentity())
	zap.L().Info("Garbage Collecting identities between range", zap.Any("min", minID), zap.Any("max", maxID))

	return &IdentityReaper{
		gcInterval:     defaults.KVstoreLeaseTTL,
		gcRateInterval: time.Minute,
		gcRateLimit:    2500,

		rateLimiter: rate.NewLimiter(
			time.Minute,
			2500,
		),

		allocator: allocator.NewAllocatorForGC(backend, allocator.WithMin(minID), allocator.WithMax(maxID)),
	}, nil
}

func (r *IdentityReaper) Run(ctx context.Context) error {
	keysToDeletePrev := map[string]uint64{}

	gcTimer, gcTimerDone := inctimer.New()
	defer gcTimerDone()
	defer r.rateLimiter.Stop()

	for {
		now := time.Now()

		keysToDelete, _, err := r.allocator.RunGC(r.rateLimiter, keysToDeletePrev)
		gcDuration := time.Since(now)
		if err != nil {
			zap.L().Error("Unable to run security identity garbage collector", zap.Error(err))
		} else {
			keysToDeletePrev = keysToDelete
		}

		if r.gcInterval <= gcDuration {
			zap.L().Warn("Identity garbage collection took longer than the GC interval",
				zap.Duration("interval", r.gcInterval),
				zap.Duration("duration", gcDuration),
				zap.String("hint", "Is there a ratelimit configured on the kvstore client or server?"),
			)

			// Don't sleep because we have a lot of work to do,
			// but check if the context was canceled before running
			// another gc cycle.
			if ctx.Err() != nil {
				return nil
			}
		} else {
			select {
			case <-ctx.Done():
				return nil
			case <-gcTimer.After(r.gcInterval - gcDuration):
			}
		}

		zap.L().Debug("Will delete identities if they are still unused", zap.Any("identities-to-delete", keysToDeletePrev))
	}
}
