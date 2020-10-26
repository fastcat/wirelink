package server

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/signing"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
)

func TestLinkServer_formatFacts(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)
	// constant data here so that we can have constant string asserts easily
	k1s := "GLTtd/FIr9+BfZJ+mFlel97VK0ED33ENxDDUPV/ck3A="
	k1 := testutils.MustParseKey(t, k1s)
	ep1 := &net.UDPAddr{
		IP:   util.NormalizeIP(net.IPv4(100, 1, 2, 3)),
		Port: 1234,
	}
	ipn1 := net.IPNet{
		IP:   util.NormalizeIP(net.IPv4(100, 2, 3, 4)),
		Mask: net.CIDRMask(24, 32),
	}
	pcsUnhealthy60m := (&apply.PeerConfigState{}).Update(
		&wgtypes.Peer{LastHandshakeTime: now.Add(-60 * time.Minute)},
		"",
		false,
		time.Time{},
		nil,
		now,
		nil,
	)

	type fields struct {
		config     *config.Server
		peerConfig *peerConfigSet
	}
	type args struct {
		facts []*fact.Fact
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       string
		wantRegexp bool
	}{
		{
			"empty",
			fields{
				&config.Server{},
				newPeerConfigSet(),
			},
			args{nil},
			fmt.Sprintf("Current facts:\nCurrent peers:\nSelf: Version %s on {} [<nil>]:0 (leaf, quiet)", internal.Version),
			false,
		},
		{
			"one fact",
			fields{
				&config.Server{},
				newPeerConfigSet(),
			},
			args{[]*fact.Fact{
				facts.EndpointFactFull(ep1, &k1, expires),
			}},
			fmt.Sprintf(
				"Current facts:\n"+
					"{a:e s:%s v:100.1.2.3:1234 ttl:255.000}\n"+
					"Current peers:\n"+
					"Self: Version %s on {} [<nil>]:0 (leaf, quiet)",
				k1s,
				internal.Version,
			),
			false,
		},
		{
			"two facts reordered",
			fields{
				&config.Server{},
				newPeerConfigSet(),
			},
			args{[]*fact.Fact{
				facts.EndpointFactFull(ep1, &k1, expires),
				facts.AllowedIPFactFull(ipn1, &k1, expires),
			}},
			fmt.Sprintf(
				"Current facts:\n"+
					"{a:a s:%s v:100.2.3.4/24 ttl:255.000}\n"+
					"{a:e s:%s v:100.1.2.3:1234 ttl:255.000}\n"+
					"Current peers:\n"+
					"Self: Version %s on {} [<nil>]:0 (leaf, quiet)",
				k1s,
				k1s,
				internal.Version,
			),
			false,
		},
		{
			"one unhealthy peer",
			fields{
				&config.Server{},
				&peerConfigSet{
					map[wgtypes.Key]*apply.PeerConfigState{
						k1: pcsUnhealthy60m,
					},
					&sync.Mutex{},
				},
			},
			args{},
			fmt.Sprintf(
				"Current facts:\n"+
					"Current peers:\n"+
					"Peer %s is unhealthy (%v)\n"+
					"Self: Version %s on {} [<nil>]:0 (leaf, quiet)",
				k1s,
				60*time.Minute,
				internal.Version,
			),
			false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				config:      tt.fields.config,
				peerConfig:  tt.fields.peerConfig,
				stateAccess: &sync.Mutex{},
				// just a placeholder for code that wants to check the local public key
				signer: &signing.Signer{},
			}
			got := s.formatFacts(now, tt.args.facts)
			if tt.wantRegexp {
				assert.Regexp(t, tt.want, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestLinkServer_UpdateRouterState(t *testing.T) {
	type fields struct {
		config *config.Server
	}
	type args struct {
		dev *wgtypes.Device
	}
	type test struct {
		name       string
		fields     fields
		args       args
		wantFields fields
	}
	generate := func(givenRouter, givenAuto, remoteRouter, wantRouter bool) test {
		peerAIP := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 32)
		if remoteRouter {
			peerAIP.Mask = net.CIDRMask(24, 32)
		}
		givenRouterDesc := "leaf"
		if givenRouter {
			givenRouterDesc = "router"
		}
		givenAutoDesc := "fixed"
		if givenAuto {
			givenAutoDesc = "auto"
		}
		remoteDesc := "leaf"
		if remoteRouter {
			remoteDesc = "router"
		}
		wantRouterDesc := "leaf"
		if wantRouter {
			wantRouterDesc = "router"
		}
		return test{
			fmt.Sprintf("given %s,%s with remote %s then %s", givenRouterDesc, givenAutoDesc, remoteDesc, wantRouterDesc),
			fields{&config.Server{
				IsRouterNow:      givenRouter,
				AutoDetectRouter: givenAuto,
			}},
			args{&wgtypes.Device{Peers: []wgtypes.Peer{{
				AllowedIPs: []net.IPNet{peerAIP},
			}}}},
			fields{&config.Server{
				IsRouterNow:      wantRouter,
				AutoDetectRouter: givenAuto,
			}},
		}
	}
	tests := []test{
		generate(false, false, false, false), // no-auto, keep as is
		generate(false, false, true, false),  // no-auto, keep as is
		generate(false, true, false, true),   // auto, no other router, we must be
		generate(false, true, true, false),   // auto, other router, we're not
		generate(true, false, false, true),   // no-auto, keep as is
		generate(true, false, true, true),    // no-auto, keep as is
		generate(true, true, false, true),    // auto, no other router, we must be
		generate(true, true, true, false),    // auto, other router, we're not
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, logChanges := range []bool{true, false} {
				s := &LinkServer{
					config: tt.fields.config,
				}
				s.UpdateRouterState(tt.args.dev, logChanges)
				assert.Equal(t, tt.wantFields.config, s.config)
			}
		})
	}
}
