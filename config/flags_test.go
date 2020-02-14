package config

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	fakeName := "wirelink_test"
	envArg := func(arg, value string) []string {
		return []string{
			strings.ToUpper(fmt.Sprintf("%s_%s", fakeName, arg)),
			value,
		}
	}
	wgIface := fmt.Sprintf("wgFake%d", rand.Int())

	tests := []struct {
		name      string
		args      []string
		env       [][]string
		wantRet   *ServerData
		assertion require.ErrorAssertionFunc
	}{
		{
			"empty",
			nil,
			nil,
			&ServerData{Iface: "wg0"},
			require.NoError,
		},
		{
			"arg iface",
			[]string{"--iface", wgIface},
			nil,
			&ServerData{Iface: wgIface},
			require.NoError,
		},
		{
			"env iface",
			nil,
			[][]string{envArg("iface", wgIface)},
			&ServerData{Iface: wgIface},
			require.NoError,
		},
		{
			"help",
			[]string{"--help"},
			nil,
			nil,
			require.NoError,
		},
		{
			"bogus arg",
			[]string{fmt.Sprintf("--garbage-%d", rand.Int())},
			nil,
			nil,
			require.Error,
		},
		{
			"router",
			[]string{"--router"},
			nil,
			&ServerData{Iface: "wg0", Router: boolPtr(true)},
			require.NoError,
		},
		{
			"router=true",
			[]string{"--router=true"},
			nil,
			&ServerData{Iface: "wg0", Router: boolPtr(true)},
			require.NoError,
		},
		{
			"router=false",
			[]string{"--router=false"},
			nil,
			&ServerData{Iface: "wg0", Router: boolPtr(false)},
			require.NoError,
		},
		// TODO: more tests
		// many will need a way to capture/sniff log output
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// make sure it doesn't use any real configs on the system
			configPathKey := fmt.Sprintf("%s_%s", strings.ToUpper(fakeName), "CONFIG_PATH")
			os.Setenv(configPathKey, "./testdata/")
			defer os.Unsetenv(configPathKey)

			// set per-test env, clear it at the end
			for _, envPair := range tt.env {
				os.Setenv(envPair[0], envPair[1])
				defer os.Unsetenv(envPair[0])
			}

			args := append([]string{fakeName}, tt.args...)
			flags, vcfg := Init(args)
			gotRet, err := Parse(flags, vcfg, args)
			tt.assertion(t, err)
			assert.Equal(t, tt.wantRet, gotRet)
		})
	}
}
