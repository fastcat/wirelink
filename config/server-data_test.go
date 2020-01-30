package config

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/trust"

	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerData_Parse(t *testing.T) {
	k1 := testutils.MustKey(t)
	name := fmt.Sprintf("%c%c%c", letter(), letter(), letter())
	iface := fmt.Sprintf("wg%d", rand.Int31())
	wan := fmt.Sprintf("eth%d", rand.Int31())
	docker := fmt.Sprintf("docker%d", rand.Int31())
	port := rand.Intn(65535)
	chatty := boolean()
	fe := boolean()
	basic := boolean()

	type fields struct {
		Iface        string
		Port         int
		Router       *bool
		Chatty       bool
		Peers        []PeerData
		ReportIfaces []string
		HideIfaces   []string
		Debug        bool
		Dump         bool
		Help         bool
		Version      bool
		configPath   string
	}
	type args struct {
		vcfg *viper.Viper
		wgc  internal.WgClient
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantRet *Server
		wantErr bool
	}{
		{
			"bad report glob",
			fields{
				Iface:        iface,
				Port:         port,
				ReportIfaces: []string{"wg[0-"},
			},
			args{nil, nil},
			nil,
			true,
		},
		{
			"bad hide glob",
			fields{
				Iface:      iface,
				Port:       port,
				HideIfaces: []string{"wg[0-"},
			},
			args{nil, nil},
			nil,
			true,
		},
		{
			"forced router true",
			fields{
				Iface:  iface,
				Port:   port,
				Router: boolPtr(true),
			},
			args{nil, nil},
			&Server{
				Iface:            iface,
				Port:             port,
				AutoDetectRouter: false,
				IsRouterNow:      true,
				Peers:            Peers{},
			},
			false,
		},
		{
			"forced router false",
			fields{
				Iface:  iface,
				Port:   port,
				Router: boolPtr(false),
			},
			args{nil, nil},
			&Server{
				Iface:            iface,
				Port:             port,
				AutoDetectRouter: false,
				IsRouterNow:      false,
				Peers:            Peers{},
			},
			false,
		},
		{
			"bad peer",
			fields{
				Iface: iface,
				Port:  port,
				Peers: []PeerData{
					PeerData{
						PublicKey: "gobbledygook",
					},
				},
			},
			args{nil, nil},
			nil,
			true,
		},
		{
			"good: all the things",
			fields{
				Iface:        iface,
				Port:         port,
				Router:       nil,
				Chatty:       chatty,
				ReportIfaces: []string{wan},
				HideIfaces:   []string{docker},
				Peers: []PeerData{
					PeerData{
						PublicKey:     k1.String(),
						Name:          name,
						Trust:         trust.Names[trust.DelPeer],
						FactExchanger: fe,
						Basic:         basic,
						Endpoints:     []string{"127.0.0.1:1"},
						AllowedIPs:    []string{"192.0.2.1/32"},
					},
				},
			},
			args{nil, nil},
			&Server{
				Iface:            iface,
				Port:             port,
				AutoDetectRouter: true,
				IsRouterNow:      false,
				Chatty:           chatty,
				ReportIfaces:     []string{wan},
				HideIfaces:       []string{docker},
				Peers: Peers{
					k1: &Peer{
						Name:          name,
						Trust:         trustPtr(trust.DelPeer),
						FactExchanger: fe,
						Basic:         basic,
						Endpoints: []PeerEndpoint{
							PeerEndpoint{Host: "127.0.0.1", Port: 1},
						},
						AllowedIPs: []net.IPNet{
							testutils.MakeIPv4Net(192, 0, 2, 1, 32),
						},
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ServerData{
				Iface:        tt.fields.Iface,
				Port:         tt.fields.Port,
				Router:       tt.fields.Router,
				Chatty:       tt.fields.Chatty,
				Peers:        tt.fields.Peers,
				ReportIfaces: tt.fields.ReportIfaces,
				HideIfaces:   tt.fields.HideIfaces,
				Debug:        tt.fields.Debug,
				Dump:         tt.fields.Dump,
				Help:         tt.fields.Help,
				Version:      tt.fields.Version,
				configPath:   tt.fields.configPath,
			}
			gotRet, err := s.Parse(tt.args.vcfg, tt.args.wgc)
			if tt.wantErr {
				require.NotNil(t, err, "ServerData.Parse() error")
			} else {
				require.Nil(t, err, "ServerData.Parse() error")
			}
			assert.Equal(t, tt.wantRet, gotRet, "ServerData.Parse()")
		})
	}
}
