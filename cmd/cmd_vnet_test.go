package cmd

import (
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/internal/networking/vnet"
	"github.com/fastcat/wirelink/trust"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func srcDirectory() string {
	_, filename, _, _ := runtime.Caller(1)
	return path.Dir(filename)
}

const wgPort = 51820

func Test_Cmd_VNet1(t *testing.T) {
	if testing.Short() {
		t.Skip("vnet acceptance tests are slow, skipping")
	}

	// setup our config path
	os.Setenv("WIREVLINK_CONFIG_PATH", srcDirectory())
	defer os.Unsetenv("WIREVLINK_CONFIG_PATH")

	w := vnet.NewWorld()
	// the internet is 100/8
	internet := w.CreateNetwork("internet")
	// lan1 is 10.1.1/24
	lan1 := w.CreateNetwork("lan1")
	// lan2 is 10.2.2/24
	lan2 := w.CreateNetwork("lan2")
	// the wireguard network is 192.168.0/24

	// host 1 is the central server
	// it is connected to the internet and to lan1
	host1 := w.CreateHost("core")
	defer host1.Close()
	h1e0 := host1.AddPhy("eth0")
	h1e0.AddAddr(net.IPNet{IP: net.IPv4(100, 1, 1, 1), Mask: net.CIDRMask(24, 32)})
	h1e0.AttachToNetwork(internet)
	h1e1 := host1.AddPhy("eth1")
	h1e1.AddAddr(net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)})
	h1e1.AttachToNetwork(lan1)
	h1w0 := host1.AddTun("wg0")
	h1w0.GenerateKeys()
	h1w0.AddAddr(net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(24, 32)})
	h1w0.Listen(wgPort)
	// don't add any peers, we'll do that with config

	// clients are roaming devices that are sometimes on lan1,
	// sometimes on lan2, sometimes maybe neither, initially nowhere
	addClient := func(i int) *vnet.Host {
		name := fmt.Sprintf("client%d", i)
		client := w.CreateHost(name)

		// client NICs are initially not connected to a network, though they are addressed for internet/lan1
		ce0 := client.AddPhy("eth0")
		ce0.AddAddr(net.IPNet{IP: net.IPv4(100, 1, 1, byte(1+i)), Mask: net.CIDRMask(24, 32)})
		ce1 := client.AddPhy("wl0")
		ce1.AddAddr(net.IPNet{IP: net.IPv4(10, 0, 0, byte(1+i)), Mask: net.CIDRMask(24, 32)})

		// we name client interfaces wg1 to make loading the test json easier
		cwg := client.AddTun("wg1")
		cwg.GenerateKeys()
		cwg.AddAddr(net.IPNet{IP: net.IPv4(192, 168, 0, byte(1+i)), Mask: net.CIDRMask(24, 32)})
		cwg.Listen(wgPort)

		return client
	}

	client1 := addClient(1)
	defer client1.Close()
	client2 := addClient(2)
	defer client2.Close()

	host1cmd := New([]string{"wirevlink", "--iface=wg0", "--router=true"})
	client1cmd := New([]string{"wirevlink", "--iface=wg1", "--router=false"})
	client2cmd := New([]string{"wirevlink", "--iface=wg1", "--router=false"})

	require.NoError(t, host1cmd.Init(host1.Wrap()))
	require.NoError(t, client1cmd.Init(client1.Wrap()))
	require.NoError(t, client2cmd.Init(client2.Wrap()))

	// hack in configs for peers
	host1cmd.Config.Peers[h1w0.PublicKey()] = &config.Peer{
		Name:  host1.Name(),
		Trust: trust.Ptr(trust.Membership),
	}
	c1pub := client1.Interface("wg1").(*vnet.Tunnel).PublicKey()
	c2pub := client2.Interface("wg1").(*vnet.Tunnel).PublicKey()
	host1cmd.Config.Peers[c1pub] = &config.Peer{
		Name: client1.Name(),
	}
	host1cmd.Config.Peers[c2pub] = &config.Peer{
		Name: client2.Name(),
	}
	// TODO: name & explicitly configure client1 & client2
	client1cmd.Config.Peers[h1w0.PublicKey()] = &config.Peer{
		Name:  host1.Name(),
		Trust: trust.Ptr(trust.Membership),
		Endpoints: []config.PeerEndpoint{{
			Host: "100.1.1.1",
			Port: wgPort + 1,
		}},
	}
	client2cmd.Config.Peers[h1w0.PublicKey()] = &config.Peer{
		Name:  host1.Name(),
		Trust: trust.Ptr(trust.Membership),
		Endpoints: []config.PeerEndpoint{{
			Host: "100.1.1.1",
			Port: wgPort + 1,
		}},
	}

	eg := &errgroup.Group{}
	eg.Go(host1cmd.Run)
	eg.Go(client1cmd.Run)
	eg.Go(client2cmd.Run)

	<-time.After(1 * time.Second)
	host1cmd.Server.RequestPrint()
	client1cmd.Server.RequestPrint()
	client2cmd.Server.RequestPrint()

	<-time.After(1 * time.Second)
	host1cmd.Server.RequestStop()
	client1cmd.Server.RequestStop()
	client2cmd.Server.RequestStop()

	err := eg.Wait()
	assert.NoError(t, err)

	assert.NotNil(t, lan2)
}
