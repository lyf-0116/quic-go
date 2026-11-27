package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestReplayKeyCoversTicketAndRequest(t *testing.T) {
	ticket := []byte("session-ticket")
	request := []byte("POST /charge amount=1")

	key := NewReplayKey(ticket, request)
	require.False(t, key.IsZero())
	require.Equal(t, key, NewReplayKey(ticket, request))

	// changing either component must change the key
	require.NotEqual(t, key, NewReplayKey([]byte("other-ticket"), request))
	require.NotEqual(t, key, NewReplayKey(ticket, []byte("POST /charge amount=2")))

	// keying on the ticket alone would collapse these two requests
	differentRequest := NewReplayKey(ticket, []byte("GET /status"))
	require.NotEqual(t, key, differentRequest)
	require.NotEqual(t, key.TicketID, differentRequest.RequestDigest)
}

func TestLocalReplayCacheCheckAndStore(t *testing.T) {
	cache := NewReplayCache()
	key := NewReplayKey([]byte("ticket"), []byte("request"))

	replayed, err := cache.CheckAndStore(key)
	require.NoError(t, err)
	require.False(t, replayed)

	replayed, err = cache.CheckAndStore(key)
	require.NoError(t, err)
	require.True(t, replayed)
	require.True(t, cache.Seen(key))
	require.True(t, cache.Has(key))
}

func TestLocalReplayCacheCompositeKey(t *testing.T) {
	cache := NewReplayCache()
	ticket := []byte("ticket")
	first := NewReplayKey(ticket, []byte("request-1"))
	second := NewReplayKey(ticket, []byte("request-2"))

	require.False(t, cache.Seen(first))
	// same ticket, different request: must not be treated as a replay
	require.False(t, cache.Seen(second))
	// the first request is now a replay
	require.True(t, cache.Seen(first))
}

func TestLocalReplayCacheTTL(t *testing.T) {
	now := time.Now()
	cache := NewLocalReplayCache(time.Minute, 10)
	cache.now = func() time.Time { return now }

	key := NewReplayKey([]byte("ticket"), []byte("request"))
	require.False(t, cache.Seen(key))
	require.True(t, cache.Seen(key))

	// after the entry expires, the same key is accepted again
	now = now.Add(2 * time.Minute)
	require.False(t, cache.Has(key))
	require.False(t, cache.Seen(key))
}

func TestLocalReplayCacheEvictsLRU(t *testing.T) {
	cache := NewLocalReplayCache(time.Hour, 2)

	keys := []ReplayKey{
		NewReplayKey(nil, []byte("a")),
		NewReplayKey(nil, []byte("b")),
	}
	cache.Add(keys[0])
	cache.Add(keys[1])

	// touch keys[0] so that keys[1] becomes the least recently used entry
	require.True(t, cache.Has(keys[0]))
	cache.Add(NewReplayKey(nil, []byte("c")))

	require.True(t, cache.Has(keys[0]))
	require.False(t, cache.Has(keys[1]))
	require.Equal(t, 2, cache.Len())
}

func TestSharedReplayCache(t *testing.T) {
	original := SharedReplayCache()
	defer SetSharedReplayCache(original)

	shared := NewReplayCache()
	SetSharedReplayCache(shared)
	require.Same(t, shared, SharedReplayCache())

	// two "instances" sharing the cache observe each other's fingerprints
	key := NewReplayKey([]byte("shared-ticket"), []byte("shared-request"))
	replayed, err := SharedReplayCache().CheckAndStore(key)
	require.NoError(t, err)
	require.False(t, replayed)
	replayed, err = SharedReplayCache().CheckAndStore(key)
	require.NoError(t, err)
	require.True(t, replayed)

	SetSharedReplayCache(nil)
	require.NotNil(t, SharedReplayCache())
}

func TestEarlyDataReplayGuard(t *testing.T) {
	cache := NewReplayCache()
	ticket := []byte("ticket")
	frame := &wire.StreamFrame{StreamID: 0, Offset: 0, Fin: true, Data: []byte("POST /charge")}

	first := newEarlyDataReplayGuard(cache)
	replayed, err := first.checkStreamFrame(ticket, frame)
	require.NoError(t, err)
	require.False(t, replayed)

	// an in-connection duplicate is not reported as a cross-connection replay
	replayed, err = first.checkStreamFrame(ticket, frame)
	require.NoError(t, err)
	require.False(t, replayed)

	// a new connection (new guard) presenting the same ticket and frame replays
	second := newEarlyDataReplayGuard(cache)
	replayed, err = second.checkStreamFrame(ticket, &wire.StreamFrame{
		StreamID: 0, Offset: 0, Fin: true, Data: append([]byte(nil), frame.Data...),
	})
	require.NoError(t, err)
	require.True(t, replayed)

	// a different request on the same ticket is fine
	replayed, err = second.checkStreamFrame(ticket, &wire.StreamFrame{
		StreamID: 0, Offset: 0, Fin: true, Data: []byte("GET /status"),
	})
	require.NoError(t, err)
	require.False(t, replayed)

	// the same request on a different ticket is a distinct key
	otherTicket := newEarlyDataReplayGuard(cache)
	replayed, err = otherTicket.checkStreamFrame([]byte("other-ticket"), frame)
	require.NoError(t, err)
	require.False(t, replayed)
}
