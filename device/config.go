package device

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

// ConfigureDevice wraps the underlying wgctrl method
func (d *Device) ConfigureDevice(cfg wgtypes.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.dirty = true
	err := d.ctrl.ConfigureDevice(d.iface, cfg)
	return err
}
