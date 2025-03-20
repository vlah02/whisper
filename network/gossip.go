package network

import (
	"sync"
	"time"
)

// GossipManager tracks the messages that have been seen by a peer
// to prevent duplicate processing and redundant broadcasts.
type GossipManager struct {
	seenMessages map[string]time.Time // maps message IDs to the time they were seen
	mu           sync.Mutex           // protects access to seenMessages
	ttl          time.Duration        // time-to-live for each message entry
}

// NewGossipManager creates a new GossipManager with the specified TTL.
// It also starts a background cleanup loop to remove stale message entries.
func NewGossipManager(ttl time.Duration) *GossipManager {
	gm := &GossipManager{
		seenMessages: make(map[string]time.Time),
		ttl:          ttl,
	}
	go gm.cleanupLoop()
	return gm
}

// Seen checks if a message with the provided msgID has already been seen.
// Returns true if the message exists in the seenMessages map.
func (gm *GossipManager) Seen(msgID string) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	_, ok := gm.seenMessages[msgID]
	return ok
}

// MarkSeen records the message with the given msgID as seen, along with the current time.
func (gm *GossipManager) MarkSeen(msgID string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.seenMessages[msgID] = time.Now()
}

// cleanupLoop runs continuously, periodically cleaning up stale message entries
// that have exceeded the configured TTL.
func (gm *GossipManager) cleanupLoop() {
	ticker := time.NewTicker(gm.ttl)
	defer ticker.Stop()
	for range ticker.C {
		gm.removeExpiredMessages()
	}
}

// removeExpiredMessages iterates through the seenMessages map and deletes entries
// that are older than the TTL.
func (gm *GossipManager) removeExpiredMessages() {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	now := time.Now()
	for id, t := range gm.seenMessages {
		if now.Sub(t) > gm.ttl {
			delete(gm.seenMessages, id)
		}
	}
}
