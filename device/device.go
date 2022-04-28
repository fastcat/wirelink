package device

import (
	"sync"

	"github.com/fastcat/wirelink/internal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Device wraps a WgClient and an associated device name
type Device struct {
	mu      sync.Mutex
	ctrl    internal.WgClient
	iface   string
	ownCtrl bool

	state   *wgtypes.Device
	dirty   bool
	lastErr error
}

// New creates a new device from an already open control interface. The Close()
// method of the returned Device will be a no-op.
func New(
	ctrl internal.WgClient,
	iface string,
) (*Device, error) {
	dev := &Device{ctrl: ctrl, iface: iface}
	if err := dev.read(); err != nil {
		return nil, err
	}
	return dev, nil
}

// Take is the same as New, except that it takes ownership of the control
// interface if initialization is successful.
func Take(
	ctrl internal.WgClient,
	iface string,
) (*Device, error) {
	dev := &Device{ctrl: ctrl, iface: iface, ownCtrl: true}
	if err := dev.read(); err != nil {
		return nil, err
	}
	return dev, nil
}

// TODO: Open()

// Close closes the underlying control interface, if the Device owns it. It is
// not safe to call Close if other goroutines using the device are active.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ownCtrl {
		if err := d.ctrl.Close(); err != nil {
			return err
		}
		d.ctrl = nil
	}
	return nil
}

// read updates the internal cache of the device state. It must be called with
// the state mutex locked, or from some context such as initialization where it
// is not possible for another goroutine to be accessing the device
// concurrently.
func (d *Device) read() error {
	s, err := d.ctrl.Device(d.iface)
	d.lastErr = err
	if err != nil {
		d.dirty = true
		return err
	}
	d.state = s
	d.dirty = false
	return nil
}

// State gets the current device state. It will attempt to refresh it if dirty.
// If refresh fails, it will return the last state along with the refresh error.
// The returned state will never be nil, because New/Open will refuse to create
// a Device if they cannot read an initial state.
func (d *Device) State() (*wgtypes.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dirty {
		// ignore the error, if the read fails we just return the last state
		_ = d.read()
	}
	return d.state, d.lastErr
}

// Refresh is like State(), but always re-reads the device state, even if it
// isn't dirty.
// func (d *Device) Refresh() (*wgtypes.Device, error) {
// 	d.mu.Lock()
// 	defer d.mu.Unlock()
// 	_ = d.read()
// 	return d.state, d.lastErr
// }

// Dirty marks the device state dirty forcing the next read to refresh the data.
func (d *Device) Dirty() {
	// for tests
	if d == nil {
		return
	}

	d.mu.Lock()
	d.dirty = true
	d.mu.Unlock()
}
