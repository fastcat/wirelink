package config

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
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
		ConfigPath   string
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
					{
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
					{
						PublicKey:     k1.String(),
						Name:          name,
						Trust:         trust.Names[trust.Membership],
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
						Trust:         trust.Ptr(trust.Membership),
						FactExchanger: fe,
						Basic:         basic,
						Endpoints: []PeerEndpoint{
							{Host: "127.0.0.1", Port: 1},
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
				ConfigPath:   tt.fields.ConfigPath,
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

func TestServerData_Dump(t *testing.T) {
	fakeName := "wirelink_test"
	envArg := func(arg, value string) []string {
		return []string{
			strings.ToUpper(fmt.Sprintf("%s_%s", fakeName, arg)),
			value,
		}
	}
	wgIface := fmt.Sprintf("wgFake%d", rand.Int())
	configPath := "./testdata/"

	tests := []struct {
		name     string
		args     []string
		env      [][]string
		wantJSON interface{}
	}{
		{
			"empty",
			nil,
			nil,
			map[string]interface{}{
				"chatty":      false,
				"config-path": configPath,
				"debug":       false,
				"iface":       "wg0",
			},
		},
		{
			"arg iface",
			[]string{"--iface", wgIface},
			nil,
			map[string]interface{}{
				"chatty":      false,
				"config-path": configPath,
				"debug":       false,
				"iface":       wgIface,
			},
		},
		{
			"env iface",
			nil,
			[][]string{envArg("iface", wgIface)},
			map[string]interface{}{
				"chatty":      false,
				"config-path": configPath,
				"debug":       false,
				"iface":       wgIface,
			},
		},
		{
			"arg chatty",
			[]string{"--chatty"},
			nil,
			map[string]interface{}{
				"chatty":      true,
				"config-path": configPath,
				"debug":       false,
				"iface":       "wg0",
			},
		},
		{
			"env chatty",
			nil,
			[][]string{envArg("chatty", "true")},
			map[string]interface{}{
				"chatty":      true,
				"config-path": configPath,
				"debug":       false,
				"iface":       "wg0",
			},
		},
		// TODO: more
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// make sure it doesn't use any real configs on the system
			configPathKey := fmt.Sprintf("%s_%s", strings.ToUpper(fakeName), "CONFIG_PATH")
			os.Setenv(configPathKey, configPath)
			defer os.Unsetenv(configPathKey)

			// set per-test env, clear it at the end
			for _, envPair := range tt.env {
				os.Setenv(envPair[0], envPair[1])
				defer os.Unsetenv(envPair[0])
			}

			args := append([]string{fakeName}, tt.args...)
			args = append(args, "--dump")
			flags, vcfg := Init(args)
			sd, err := Parse(flags, vcfg, args)
			require.NoError(t, err)
			require.NotNil(t, sd)
			require.True(t, sd.Dump)
			outputData := testutils.CaptureOutput(t, func() {
				s, err := sd.Parse(vcfg, nil)
				require.NoError(t, err)
				require.Nil(t, s)
			})

			var dumpedObj interface{}
			require.NoError(t, json.Unmarshal(outputData, &dumpedObj))

			assert.Equal(t, tt.wantJSON, dumpedObj)
		})
	}
}
