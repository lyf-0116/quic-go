package quic

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"
)

// DefaultReplayCacheTTL is the default lifetime of entries in a replay cache.
// It is aligned with the lifetime of TLS session tickets issued by crypto/tls
// (see maxSessionTicketLifetime), so that a fingerprint is retained for exactly
// as long as the replayed 0-RTT data could be accepted.
const DefaultReplayCacheTTL = 7 * 24 * time.Hour

// defaultReplayCacheMaxEntries bounds the memory usage of the built-in replay
// cache. Once the limit is reached, the least recently used entry is evicted.
const defaultReplayCacheMaxEntries = 100_000

// ErrReplayCacheUnavailable may be returned by ReplayCache implementations when
// the shared storage cannot be reached. It is provided for implementations to
// wrap backend errors. The built-in transport integration logs check errors and
// fails open (accepts the 0-RTT frame) to preserve availability. A deployment
// requiring fail-closed semantics should provide a highly available
// ReplayCache implementation that degrades to a local cache instead of
// returning an error.
var ErrReplayCacheUnavailable = errors.New("replay cache unavailable")

// ReplayKey is the composite key used to deduplicate 0-RTT early data.
//
// The key covers both the resumption ticket (TicketID) and a digest of the
// early-data request (RequestDigest). Scoping entries by the request digest is
// essential: keying on the ticket alone would reject every further request
// resumed from the same ticket, even legitimate and unrelated ones.
//
// ReplayKey is comparable and can therefore be used as a Go map key.
type ReplayKey struct {
	// TicketID is the hash of the raw TLS session ticket (the PSK identity).
	TicketID [32]byte
	// RequestDigest is the hash of the early-data request bytes.
	RequestDigest [32]byte
}

// NewReplayKey builds a ReplayKey from the raw session ticket and the raw
// early-data request bytes. Both components are hashed with SHA-256 using
// distinct domain-separation prefixes.
func NewReplayKey(ticket, request []byte) ReplayKey {
	return ReplayKey{
		TicketID:      hashReplayComponent("quic-go/0rtt/ticket", ticket),
		RequestDigest: hashReplayComponent("quic-go/0rtt/request", request),
	}
}

// NewReplayKeyWithDigest builds a ReplayKey from the raw session ticket and an
// already computed request digest.
func NewReplayKeyWithDigest(ticket []byte, requestDigest [32]byte) ReplayKey {
	return ReplayKey{
		TicketID:      hashReplayComponent("quic-go/0rtt/ticket", ticket),
		RequestDigest: requestDigest,
	}
}

// IsZero reports whether the key contains no material.
func (k ReplayKey) IsZero() bool {
	return k == ReplayKey{}
}

// String renders the key as a hexadecimal fingerprint. It never contains the
// raw ticket or request bytes.
func (k ReplayKey) String() string {
	b := make([]byte, 0, 160)
	b = append(b, "r:"...)
	b = hex.AppendEncode(b, k.TicketID[:])
	b = append(b, '/')
	b = hex.AppendEncode(b, k.RequestDigest[:])
	return string(b)
}

func hashReplayComponent(domain string, data []byte) [32]byte {
	h := sha256.New()
	_, _ = io.WriteString(h, domain)
	_, _ = h.Write(data)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// ReplayCache stores the fingerprints of 0-RTT early data that has already been
// accepted. It is the pluggable replay-protection backend: assign an
// implementation to Config.ReplayCache on the server.
//
// CheckAndStore must atomically report whether key has been seen before and
// record it. It returns replayed == true for a duplicate. Implementations must
// expire entries after the configured time-to-live, which should not exceed the
// session ticket lifetime.
//
// Multiple server instances (including multiple quic.Transport values in the
// same process) can share one implementation. To protect a fleet behind a load
// balancer without instance-shard bypass, back the implementation with shared
// storage such as Redis; NewLocalReplayCache provides an in-process variant
// that is safe to share between Transports in one process.
type ReplayCache interface {
	CheckAndStore(key ReplayKey) (replayed bool, err error)
}

// ReplayCacheFunc adapts a function to the ReplayCache interface.
type ReplayCacheFunc func(key ReplayKey) (replayed bool, err error)

var _ ReplayCache = ReplayCacheFunc(nil)

// CheckAndStore calls f(key).
func (f ReplayCacheFunc) CheckAndStore(key ReplayKey) (bool, error) { return f(key) }

type replayCacheEntry struct {
	key       ReplayKey
	expiresAt time.Time
}

// LocalReplayCache is the built-in, concurrency-safe in-memory ReplayCache.
//
// A single LocalReplayCache can be assigned to the Config of any number of
// Transports or listeners, which makes the replay state shared between those
// instances without introducing an external dependency. For sharing across
// processes or machines, implement ReplayCache against a shared data store.
type LocalReplayCache struct {
	mutex      sync.Mutex
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	items map[ReplayKey]*list.Element // value: *replayCacheEntry
	lru   *list.List
}

var _ ReplayCache = &LocalReplayCache{}

// NewReplayCache returns a LocalReplayCache with the DefaultReplayCacheTTL and
// a bounded number of entries.
func NewReplayCache() *LocalReplayCache {
	return NewLocalReplayCache(DefaultReplayCacheTTL, defaultReplayCacheMaxEntries)
}

// NewLocalReplayCache returns a LocalReplayCache that keeps fingerprints for ttl
// and holds at most maxEntries live entries. A ttl <= 0 selects
// DefaultReplayCacheTTL, and a maxEntries <= 0 selects the default bound.
func NewLocalReplayCache(ttl time.Duration, maxEntries int) *LocalReplayCache {
	if ttl <= 0 {
		ttl = DefaultReplayCacheTTL
	}
	if maxEntries <= 0 {
		maxEntries = defaultReplayCacheMaxEntries
	}
	return &LocalReplayCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
		items:      make(map[ReplayKey]*list.Element),
		lru:        list.New(),
	}
}

// CheckAndStore atomically checks whether key is present and unexpired, and
// stores it otherwise.
func (c *LocalReplayCache) CheckAndStore(key ReplayKey) (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := c.now()
	if el, ok := c.items[key]; ok {
		entry := el.Value.(*replayCacheEntry)
		if entry.expiresAt.After(now) {
			c.lru.MoveToFront(el)
			return true, nil
		}
		c.removeElement(el)
	}

	c.evictForInsert(now)
	entry := &replayCacheEntry{key: key, expiresAt: now.Add(c.ttl)}
	c.items[key] = c.lru.PushFront(entry)
	return false, nil
}

// Seen reports whether key is currently stored and unexpired, and stores it if
// it wasn't. It is the error-free convenience wrapper around CheckAndStore for
// in-process use.
func (c *LocalReplayCache) Seen(key ReplayKey) bool {
	replayed, _ := c.CheckAndStore(key)
	return replayed
}

// Has reports whether key is present and unexpired without modifying the cache.
func (c *LocalReplayCache) Has(key ReplayKey) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	el, ok := c.items[key]
	if !ok {
		return false
	}
	entry := el.Value.(*replayCacheEntry)
	if !entry.expiresAt.After(c.now()) {
		return false
	}
	c.lru.MoveToFront(el)
	return true
}

// Add stores key with the cache's TTL. An existing unexpired entry is refreshed.
func (c *LocalReplayCache) Add(key ReplayKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if el, ok := c.items[key]; ok {
		el.Value.(*replayCacheEntry).expiresAt = c.now().Add(c.ttl)
		c.lru.MoveToFront(el)
		return
	}
	c.evictForInsert(c.now())
	entry := &replayCacheEntry{key: key, expiresAt: c.now().Add(c.ttl)}
	c.items[key] = c.lru.PushFront(entry)
}

// Len returns the number of entries currently held, including entries that have
// expired but not yet been evicted.
func (c *LocalReplayCache) Len() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return len(c.items)
}

func (c *LocalReplayCache) removeElement(el *list.Element) {
	entry := el.Value.(*replayCacheEntry)
	c.lru.Remove(el)
	delete(c.items, entry.key)
}

// evictForInsert removes expired entries and, if still at capacity, the least
// recently used entry until there is room for one new entry.
func (c *LocalReplayCache) evictForInsert(now time.Time) {
	for el := c.lru.Back(); el != nil; {
		entry := el.Value.(*replayCacheEntry)
		if entry.expiresAt.After(now) && c.lru.Len() < c.maxEntries {
			return
		}
		prev := el.Prev()
		c.removeElement(el)
		el = prev
	}
}

var (
	sharedReplayCacheMx sync.RWMutex
	sharedReplayCache   ReplayCache = NewReplayCache()
)

// SharedReplayCache returns the process-wide ReplayCache. It is shared by every
// Transport or Config that uses it, which provides cross-instance replay
// detection within the process without external dependencies.
func SharedReplayCache() ReplayCache {
	sharedReplayCacheMx.RLock()
	defer sharedReplayCacheMx.RUnlock()
	return sharedReplayCache
}

// SetSharedReplayCache replaces the process-wide cache returned by
// SharedReplayCache, for example with a Redis-backed implementation.
// Passing nil restores the built-in LocalReplayCache.
func SetSharedReplayCache(cache ReplayCache) {
	sharedReplayCacheMx.Lock()
	defer sharedReplayCacheMx.Unlock()
	if cache == nil {
		cache = NewReplayCache()
	}
	sharedReplayCache = cache
}
