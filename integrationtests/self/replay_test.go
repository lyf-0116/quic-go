package self_test

import (
	"context"
	"crypto/tls"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// replayFreezeSessionCache retains the first session ticket and ignores updates, so
// that multiple 0-RTT dials resume from the exact same session ticket.
type replayFreezeSessionCache struct {
	mu    sync.Mutex
	state *tls.ClientSessionState
}

func (c *replayFreezeSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.state != nil
}

func (c *replayFreezeSessionCache) Put(_ string, state *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil {
		c.state = state
	}
}

func TestReplayCache0RTTDuplicateRejected(t *testing.T) {
	// A single cache shared by every (here: one) server instance.
	replayCache := quic.NewReplayCache()

	serverPacketConn := newUDPConnLocalhost(t)
	serverTransport := &quic.Transport{Conn: serverPacketConn}
	defer serverTransport.Close()
	ln, err := serverTransport.ListenEarly(getTLSConfig(), getQuicConfig(&quic.Config{
		Allow0RTT:   true,
		ReplayCache: replayCache,
	}))
	require.NoError(t, err)
	defer ln.Close()

	var mu sync.Mutex
	processed := make(map[string]int)

	// Obtain a 0-RTT enabled ticket and pin it in the freezing cache.
	// This helper drives its own Accept for the ticket connection, so it must
	// run before the request-handling Accept loop is started.
	clientTLSConf := dialAndReceiveTicket(t, ln, newUDPConnLocalhost(t), &replayFreezeSessionCache{})

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn *quic.Conn) {
				str, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				data, err := io.ReadAll(str)
				if err != nil {
					// A replayed connection is torn down before its frames are delivered.
					return
				}
				mu.Lock()
				processed[string(data)]++
				mu.Unlock()
				_, _ = str.Write(data)
				_ = str.Close()
			}(conn)
		}
	}()

	sendEarly := func(payload []byte) ([]byte, bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
		defer tr.Close()
		conn, err := tr.DialEarly(ctx, ln.Addr(), clientTLSConf, getQuicConfig(nil))
		if err != nil {
			return nil, false, err
		}
		defer conn.CloseWithError(0, "")
		str, err := conn.OpenStream()
		if err != nil {
			return nil, conn.ConnectionState().Used0RTT, err
		}
		if _, err := str.Write(payload); err != nil {
			return nil, conn.ConnectionState().Used0RTT, err
		}
		if err := str.Close(); err != nil {
			return nil, conn.ConnectionState().Used0RTT, err
		}
		data, err := io.ReadAll(str)
		return data, conn.ConnectionState().Used0RTT, err
	}

	requestA := []byte("POST /charge?amount=42")
	echo, used0RTT, err := sendEarly(requestA)
	require.NoError(t, err)
	require.Equal(t, requestA, echo)
	require.True(t, used0RTT)

	// Replaying the same ticket and the same request is rejected.
	_, _, err = sendEarly(requestA)
	require.Error(t, err)

	// A different request resumed from the same ticket must still succeed.
	requestB := []byte("POST /order?item=7")
	echo, _, err = sendEarly(requestB)
	require.NoError(t, err)
	require.Equal(t, requestB, echo)

	// Give a potentially missed duplicate no chance to land, then verify the
	// first request was processed exactly once.
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, processed[string(requestA)], "replayed request must not be processed again")
	require.Equal(t, 1, processed[string(requestB)])
}
