package server

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/signing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinkServer_configurePeers(t *testing.T) {
	type fields struct {
		bootID          uuid.UUID
		stateAccess     *sync.Mutex
		config          *config.Server
		net             networking.Environment
		conn            *net.UDPConn
		addr            net.UDPAddr
		ctrl            internal.WgClient
		eg              *errgroup.Group
		ctx             context.Context
		cancel          context.CancelFunc
		peerKnowledge   *peerKnowledgeSet
		peerConfig      *peerConfigSet
		signer          *signing.Signer
		printsRequested *int32
	}
	type args struct {
		factsRefreshed <-chan []*fact.Fact
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				bootID:          tt.fields.bootID,
				stateAccess:     tt.fields.stateAccess,
				config:          tt.fields.config,
				net:             tt.fields.net,
				conn:            tt.fields.conn,
				addr:            tt.fields.addr,
				ctrl:            tt.fields.ctrl,
				eg:              tt.fields.eg,
				ctx:             tt.fields.ctx,
				cancel:          tt.fields.cancel,
				peerKnowledge:   tt.fields.peerKnowledge,
				peerConfig:      tt.fields.peerConfig,
				signer:          tt.fields.signer,
				printsRequested: tt.fields.printsRequested,
			}
			err := s.configurePeers(tt.args.factsRefreshed)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}

			// TODO: check mocks
		})
	}
}

func TestLinkServer_deletePeers(t *testing.T) {
	type fields struct {
		bootID          uuid.UUID
		stateAccess     *sync.Mutex
		config          *config.Server
		net             networking.Environment
		conn            *net.UDPConn
		addr            net.UDPAddr
		ctrl            internal.WgClient
		eg              *errgroup.Group
		ctx             context.Context
		cancel          context.CancelFunc
		peerKnowledge   *peerKnowledgeSet
		peerConfig      *peerConfigSet
		signer          *signing.Signer
		printsRequested *int32
	}
	type args struct {
		dev        *wgtypes.Device
		removePeer map[wgtypes.Key]bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				bootID:          tt.fields.bootID,
				stateAccess:     tt.fields.stateAccess,
				config:          tt.fields.config,
				net:             tt.fields.net,
				conn:            tt.fields.conn,
				addr:            tt.fields.addr,
				ctrl:            tt.fields.ctrl,
				eg:              tt.fields.eg,
				ctx:             tt.fields.ctx,
				cancel:          tt.fields.cancel,
				peerKnowledge:   tt.fields.peerKnowledge,
				peerConfig:      tt.fields.peerConfig,
				signer:          tt.fields.signer,
				printsRequested: tt.fields.printsRequested,
			}
			err := s.deletePeers(tt.args.dev, tt.args.removePeer)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}

			// TODO: check mocks
		})
	}
}

func TestLinkServer_configurePeer(t *testing.T) {
	type fields struct {
		bootID          uuid.UUID
		stateAccess     *sync.Mutex
		config          *config.Server
		net             networking.Environment
		conn            *net.UDPConn
		addr            net.UDPAddr
		ctrl            internal.WgClient
		eg              *errgroup.Group
		ctx             context.Context
		cancel          context.CancelFunc
		peerKnowledge   *peerKnowledgeSet
		peerConfig      *peerConfigSet
		signer          *signing.Signer
		printsRequested *int32
	}
	type args struct {
		inputState       *apply.PeerConfigState
		self             *wgtypes.Key
		peer             *wgtypes.Peer
		facts            []*fact.Fact
		allowDeconfigure bool
		allowAdd         bool
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantState *apply.PeerConfigState
		wantErr   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				bootID:          tt.fields.bootID,
				stateAccess:     tt.fields.stateAccess,
				config:          tt.fields.config,
				net:             tt.fields.net,
				conn:            tt.fields.conn,
				addr:            tt.fields.addr,
				ctrl:            tt.fields.ctrl,
				eg:              tt.fields.eg,
				ctx:             tt.fields.ctx,
				cancel:          tt.fields.cancel,
				peerKnowledge:   tt.fields.peerKnowledge,
				peerConfig:      tt.fields.peerConfig,
				signer:          tt.fields.signer,
				printsRequested: tt.fields.printsRequested,
			}
			gotState, err := s.configurePeer(tt.args.inputState, tt.args.self, tt.args.peer, tt.args.facts, tt.args.allowDeconfigure, tt.args.allowAdd)
			if tt.wantErr {
				require.NotNil(t, err, "LinkServer.configurePeer() error")
			} else {
				require.Nil(t, err, "LinkServer.configurePeer() error")
			}
			assert.Equal(t, tt.wantState, gotState)

			// TODO: check mocks
		})
	}
}
