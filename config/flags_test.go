package config

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/testutils"

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
	configPath := "./testdata/"

	tests := []struct {
		name        string
		args        []string
		env         [][]string
		wantRet     *ServerData
		outputCheck func(*testing.T, []byte)
		assertion   require.ErrorAssertionFunc
	}{
		{
			"empty",
			nil,
			nil,
			&ServerData{Iface: "wg0"},
			nil,
			require.NoError,
		},
		{
			"arg iface",
			[]string{"--iface", wgIface},
			nil,
			&ServerData{Iface: wgIface},
			nil,
			require.NoError,
		},
		{
			"env iface",
			nil,
			[][]string{envArg("iface", wgIface)},
			&ServerData{Iface: wgIface},
			nil,
			require.NoError,
		},
		{
			"help",
			[]string{"--help"},
			nil,
			nil,
			func(t *testing.T, output []byte) {
				text := string(output)
				assert.Contains(t, text, "Usage of "+fakeName)
				assert.Contains(t, text, internal.Version)
			},
			require.NoError,
		},
		{
			"bogus arg",
			[]string{fmt.Sprintf("--garbage-%d", rand.Int())},
			nil,
			nil,
			// TODO: want to validate output here, but it goes to stderr and so far only capturing stdout
			nil,
			require.Error,
		},
		{
			"router",
			[]string{"--router"},
			nil,
			&ServerData{Iface: "wg0", Router: boolPtr(true)},
			nil,
			require.NoError,
		},
		{
			"router=true",
			[]string{"--router=true"},
			nil,
			&ServerData{Iface: "wg0", Router: boolPtr(true)},
			nil,
			require.NoError,
		},
		{
			"router=false",
			[]string{"--router=false"},
			nil,
			&ServerData{Iface: "wg0", Router: boolPtr(false)},
			nil,
			require.NoError,
		},
		// TODO: more tests
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// make sure it doesn't use any real configs on the system
			configPathKey := fmt.Sprintf("%s_%s", strings.ToUpper(fakeName), "CONFIG_PATH")
			os.Setenv(configPathKey, configPath)
			defer os.Unsetenv(configPathKey)
			if tt.wantRet != nil {
				tt.wantRet.ConfigPath = configPath
			}

			// set per-test env, clear it at the end
			for _, envPair := range tt.env {
				os.Setenv(envPair[0], envPair[1])
				defer os.Unsetenv(envPair[0])
			}

			var gotRet *ServerData
			var err error
			outputData := testutils.CaptureOutput(t, func() {
				args := append([]string{fakeName}, tt.args...)
				flags, vcfg := Init(args)
				gotRet, err = Parse(flags, vcfg, args)
			})

			tt.assertion(t, err)
			assert.Equal(t, tt.wantRet, gotRet)

			if tt.outputCheck != nil {
				tt.outputCheck(t, outputData)
			}
		})
	}
}
