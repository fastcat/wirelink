package cmd

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/host"
	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWirelinkCmd_Init(t *testing.T) {
	const wgFake = "wgNotRealLongerThanIFNAMSIZ"
	// for safety we ensure this cannot possibly be a valid interface name
	// TODO: this is linux-specific
	require.Greater(t, len(wgFake), platformIFNAMSIZ)

	// don't use the real wirelink program name, to avoid possible collisions with
	// "real" environment settings
	const programName = "wirevlink"

	type fields struct {
		args []string
	}
	type args struct {
		netEnv networking.Environment
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		osEnv     map[string]string
		assertion require.ErrorAssertionFunc
		postCheck func(*testing.T, *WirelinkCmd)
	}{
		{
			"fail config parse: bad arg",
			fields{[]string{"--iface", wgFake, "--garbagearg"}},
			args{},
			nil,
			func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.Error(t, err, msgAndArgs...)
				require.Contains(t, err.Error(), "parse config")
			},
			func(t *testing.T, w *WirelinkCmd) {
				assert.Nil(t, w.Config)
				assert.Nil(t, w.Server)
			},
		},
		{
			"fail config parse: bad env val",
			fields{[]string{"--iface", wgFake}},
			args{},
			map[string]string{
				"_ROUTER": "NOTABOOLEAN",
			},
			func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.Error(t, err, msgAndArgs...)
				assert.ErrorContains(t, err, "parse config")
			},
			func(t *testing.T, w *WirelinkCmd) {
				assert.Nil(t, w.Config)
				assert.Nil(t, w.Server)
			},
		},
		{
			"fail config data parse: bad peer id",
			fields{[]string{"--iface", wgFake}},
			args{},
			map[string]string{
				"_CONFIG_PATH": testutils.SrcDirectory(),
			},
			func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.Error(t, err, msgAndArgs...)
				assert.ErrorContains(t, err, "load config")
				// check for the base64 error somewhere in the stack
				for unwrapped := errors.Unwrap(err); ; {
					if strings.Contains(unwrapped.Error(), "base64") {
						break
					}
					next := errors.Unwrap(unwrapped)
					if next == nil {
						require.FailNow(t, "Expected to find 'base64' somewhere in the error chain")
					}
					unwrapped = next
				}
			},
			nil,
		},
		{
			"config dump mode",
			fields{[]string{"--dump"}},
			args{},
			nil,
			require.NoError,
			func(t *testing.T, w *WirelinkCmd) {
				assert.Nil(t, w.Config)
				assert.Nil(t, w.Server)
			},
		},
		{
			"start against bogus device",
			fields{[]string{"--iface", wgFake}},
			args{},
			nil,
			func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.Error(t, err, msgAndArgs...)
				assert.ErrorContains(t, err, "create server")
				assert.ErrorContains(t, err, wgFake)
				// this is usually EPERM, but it could be EEXIST or such too
				assert.Error(t, errors.Unwrap(err))
			},
			func(t *testing.T, w *WirelinkCmd) {
				assert.NotNil(t, w.Config)
				assert.Nil(t, w.Server)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realArgs := append([]string{programName}, tt.fields.args...)
			w := &WirelinkCmd{
				args: realArgs,
			}
			defer func() {
				if w.wgc != nil {
					w.wgc.Close()
				}
				if w.Server != nil {
					w.Server.Close()
				}
			}()
			if tt.args.netEnv == nil {
				tt.args.netEnv = host.MustCreateHost()
				defer tt.args.netEnv.Close()
			}
			for k, v := range tt.osEnv {
				if k[0] == '_' {
					k = strings.ToUpper(programName) + k
				}
				cur, has := os.LookupEnv(k)
				if has {
					defer os.Setenv(k, cur)
				} else {
					defer os.Unsetenv(k)
				}
				os.Setenv(k, v)
			}
			tt.assertion(t, w.Init(tt.args.netEnv))
			if tt.postCheck != nil {
				tt.postCheck(t, w)
			}
		})
	}
}
