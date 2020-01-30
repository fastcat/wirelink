package internal

import (
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WgClient is a copy-pasta of wginternal.Client because we can't import that
type WgClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}
