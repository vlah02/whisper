package network

import (
	"sync"
	"time"
)

type GossipManager struct {
	seenMessages map[string]time.Time
	mu           sync.Mutex
	ttl          time.Duration
}

func NewGossipManager(ttl time.Duration) *GossipManager {
	gm := &GossipManager{
		seenMessages: make(map[string]time.Time),
		ttl:          ttl,
	}
	go gm.cleanupLoop()
	return gm
}

func (gm *GossipManager) Seen(msgID string) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	_, ok := gm.seenMessages[msgID]
	return ok
}

func (gm *GossipManager) MarkSeen(msgID string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.seenMessages[msgID] = time.Now()
}

func (gm *GossipManager) cleanupLoop() {
	ticker := time.NewTicker(gm.ttl)
	defer ticker.Stop()
	for {
		<-ticker.C
		gm.mu.Lock()
		for id, t := range gm.seenMessages {
			if time.Since(t) > gm.ttl {
				delete(gm.seenMessages, id)
			}
		}
		gm.mu.Unlock()
	}
}
