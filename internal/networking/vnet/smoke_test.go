package vnet

import (
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func Test_Smoke1(t *testing.T) {
	w := NewWorld()
	const wgPort = 51820

	internet := w.CreateNetwork("internet")
	lan1 := w.CreateNetwork("lan1")
	lan2 := w.CreateNetwork("lan2")

	host1 := w.CreateHost("host1")
	host2 := w.CreateHost("host2")

	host1eth0 := host1.AddPhy("eth0")
	host1eth0ip := net.IPv4(100, 1, 1, 1)
	host1eth0.AddAddr(net.IPNet{
		IP:   host1eth0ip,
		Mask: net.CIDRMask(24, 32),
	})
	host1eth1 := host1.AddPhy("eth1")
	host1eth1.AddAddr(net.IPNet{
		IP:   net.IPv4(192, 168, 0, 1),
		Mask: net.CIDRMask(24, 32),
	})

	host2eth0 := host2.AddPhy("eth0")
	host2eth0ip := net.IPv4(100, 1, 1, 2)
	host2eth0.AddAddr(net.IPNet{
		IP:   host2eth0ip,
		Mask: net.CIDRMask(24, 32),
	})
	host2eth1 := host2.AddPhy("eth1")
	host2eth1.AddAddr(net.IPNet{
		IP:   net.IPv4(192, 168, 0, 1),
		Mask: net.CIDRMask(24, 32),
	})

	host1eth0.AttachToNetwork(internet)
	defer host1eth0.DetachFromNetwork()
	host2eth0.AttachToNetwork(internet)
	defer host2eth0.DetachFromNetwork()
	host1eth1.AttachToNetwork(lan1)
	defer host1eth1.DetachFromNetwork()
	host2eth1.AttachToNetwork(lan2)
	defer host2eth1.DetachFromNetwork()

	host1wg0 := host1.AddTun("wg0")
	host2wg0 := host2.AddTun("Wg0")

	host1wg0.Listen(wgPort)
	defer host1wg0.DetachFromNetwork()
	host2wg0.Listen(wgPort)
	defer host2wg0.DetachFromNetwork()

	// verify host-to-host communication over "internet"
	s1 := host1.AddSocket(&net.UDPAddr{
		IP:   host1eth0ip,
		Port: wgPort + 1,
	})
	s2 := host2.AddSocket(&net.UDPAddr{
		IP:   host2eth0ip,
		Port: wgPort + 1,
	})

	s1c := s1.Connect()
	defer s1c.Close()
	s2c := s2.Connect()
	defer s2c.Close()

	payload := testutils.MustRandBytes(t, make([]byte, 512))
	nSent, err := s1c.WriteToUDP(payload, &net.UDPAddr{IP: host2eth0ip, Port: wgPort + 1})
	assert.NoError(t, err)
	assert.Equal(t, len(payload), nSent)

	readBuf := make([]byte, 1500)
	n, addr, err := s2c.ReadFromUDP(readBuf)
	assert.NoError(t, err)
	assert.Equal(t, len(payload), n)
	assert.Equal(t, payload, readBuf[:len(payload)])
	assert.Equal(t, &net.UDPAddr{IP: host1eth0ip, Port: wgPort + 1}, addr)
}
