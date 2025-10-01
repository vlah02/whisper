package client

import (
	"context"
	"errors"
	"sync"

	"github.com/pion/webrtc/v4"
)

type Peer struct {
	Username string
	pc       *webrtc.PeerConnection
	dc       *webrtc.DataChannel
	mu       sync.RWMutex
	closed   bool
}

func NewPeer(ctx context.Context, remote string) (*Peer, error) {
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{{
			URLs: []string{"stun:stun.l.google.com:19302"},
		}},
	}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, err
	}
	p := &Peer{Username: remote, pc: pc}
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed || s == webrtc.PeerConnectionStateClosed || s == webrtc.PeerConnectionStateDisconnected {
			p.mu.Lock()
			p.closed = true
			p.mu.Unlock()
		}
	})
	return p, nil
}

func (p *Peer) CreateDataChannel(label string) (*webrtc.DataChannel, error) {
	if p.dc != nil {
		return p.dc, nil
	}
	dc, err := p.pc.CreateDataChannel(label, nil)
	if err != nil {
		return nil, err
	}
	p.dc = dc
	return dc, nil
}

func (p *Peer) SetDataChannel(dc *webrtc.DataChannel) { p.dc = dc }

func (p *Peer) CreateOffer(ctx context.Context) (string, error) {
	o, err := p.pc.CreateOffer(nil)
	if err != nil {
		return "", err
	}
	if err := p.pc.SetLocalDescription(o); err != nil {
		return "", err
	}
	select {
	case <-p.waitICEGatheringComplete():
		return p.pc.LocalDescription().SDP, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (p *Peer) ApplyRemoteOfferAndCreateAnswer(ctx context.Context, offer string) (string, error) {
	sd := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}
	if err := p.pc.SetRemoteDescription(sd); err != nil {
		return "", err
	}
	ans, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return "", err
	}
	if err := p.pc.SetLocalDescription(ans); err != nil {
		return "", err
	}
	select {
	case <-p.waitICEGatheringComplete():
		return p.pc.LocalDescription().SDP, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (p *Peer) ApplyAnswer(answer string) error {
	sd := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}
	return p.pc.SetRemoteDescription(sd)
}

func (p *Peer) AddICECandidate(candidate string) error {
	return p.pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: candidate})
}

func (p *Peer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.dc != nil {
		_ = p.dc.Close()
	}
	return p.pc.Close()
}

func (p *Peer) waitICEGatheringComplete() <-chan struct{} {
	ch := make(chan struct{})
	if p.pc.ICEGatheringState() == webrtc.ICEGatheringStateComplete {
		close(ch)
		return ch
	}
	p.pc.OnICEGatheringStateChange(func(s webrtc.ICEGatheringState) {
		if s == webrtc.ICEGatheringStateComplete {
			close(ch)
		}
	})
	return ch
}

func (p *Peer) Send(msg string) error {
	if p.dc == nil {
		return errors.New("datachannel not ready")
	}
	if p.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return errors.New("datachannel not open yet")
	}
	return p.dc.SendText(msg)
}
