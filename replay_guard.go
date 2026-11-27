package quic

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

// earlyDataReplayGuard binds the 0-RTT STREAM frames observed on one connection
// to the session ticket and consults the configured ReplayCache.
//
// It keeps a per-connection set of frame fingerprints so that duplicated
// network copies or retransmissions of the same frame don't get reported as
// cross-connection replays of the connection itself.
type earlyDataReplayGuard struct {
	cache      ReplayCache
	ticketID   [32]byte
	ticketSet  bool
	seenFrames map[[32]byte]struct{}
}

func newEarlyDataReplayGuard(cache ReplayCache) *earlyDataReplayGuard {
	return &earlyDataReplayGuard{
		cache:      cache,
		seenFrames: make(map[[32]byte]struct{}),
	}
}

// checkStreamFrame returns replayed == true if the frame was already accepted
// on a different connection using the same session ticket.
func (g *earlyDataReplayGuard) checkStreamFrame(ticket []byte, frame *wire.StreamFrame) (replayed bool, err error) {
	if !g.ticketSet {
		g.ticketID = hashReplayComponent("quic-go/0rtt/ticket", ticket)
		g.ticketSet = true
	}

	digest := streamFrameDigest(frame)
	if _, duplicate := g.seenFrames[digest]; duplicate {
		// An identical frame was already observed on this connection. Let the
		// stream layer deal with the duplicate (e.g. a retransmitted frame).
		return false, nil
	}
	g.seenFrames[digest] = struct{}{}

	return g.cache.CheckAndStore(ReplayKey{TicketID: g.ticketID, RequestDigest: digest})
}

// streamFrameDigest hashes the stream position and payload of a STREAM frame.
// Binding the bytes to the stream ID and offset makes the fingerprint stable
// across connections while avoiding collisions between different positions.
func streamFrameDigest(frame *wire.StreamFrame) [32]byte {
	h := sha256.New()
	var meta [17]byte
	binary.BigEndian.PutUint64(meta[0:8], uint64(frame.StreamID))
	binary.BigEndian.PutUint64(meta[8:16], uint64(frame.Offset))
	if frame.Fin {
		meta[16] = 1
	}
	_, _ = h.Write([]byte("quic-go/0rtt/stream-frame"))
	_, _ = h.Write(meta[:])
	_, _ = h.Write(frame.Data)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// check0RTTStreamReplay is invoked before a 0-RTT STREAM frame is passed to the
// stream layer. A detected replay aborts processing of the early data and closes
// the replayed connection, so the duplicate request is never delivered to the
// application. Cache backend errors fail open, preserving availability; the
// ReplayCache implementation decides whether stricter behavior is appropriate.
func (c *Conn) check0RTTStreamReplay(frame *wire.StreamFrame) error {
	if c.perspective != protocol.PerspectiveServer {
		return nil
	}
	if c.config == nil || c.config.ReplayCache == nil {
		return nil
	}
	if c.earlyDataReplay == nil {
		c.earlyDataReplay = newEarlyDataReplayGuard(c.config.ReplayCache)
	}
	var ticket []byte
	if c.cryptoStreamHandler != nil {
		ticket = c.cryptoStreamHandler.ConnectionState().SessionTicketIdentity
	}
	replayed, err := c.earlyDataReplay.checkStreamFrame(ticket, frame)
	if err != nil {
		c.logger.Debugf("Replay cache check failed: %s. Accepting 0-RTT frame.", err)
		return nil
	}
	if replayed {
		c.logger.Debugf("Detected replayed 0-RTT STREAM frame. Rejecting early data.")
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "replayed 0-RTT early data rejected",
		}
	}
	return nil
}
