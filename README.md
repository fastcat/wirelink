# wirelink

## Concept

This is an experiment in implementing automatic peer-to-peer link setup in
wireguard by:

* Automatically configuring IPv6 link-local ips for each peer, derived by
  hashing the peer's public key
* Using that to automatically share information about available peers and their
  endpoints
* Using that to try to automatically setup direct connections between peers
  (when possible) instead of routing through a central "server".

## Configuration

`wirelink` will read basic configuration from:

* A config file `/etc/wireguard/wirelink.<interface>.json`
  * Some other extensions such as `.yaml` will be accepted too
  * Some settings can _only_ be set in the config file for now
* Environment variables of the form `WIRELINK_<setting>`
* Command line args (see `--help`)

### Systemd

Two systemd template units are provided:

`wl-quick@.service`, when enabled for an interface, will bind tightly to
`wg-quick@.service`.  If you are using `wg-quick`, this is the recommended
method. If you have `wg-quick@wg0` enabled, then to activate the wirelink pair,
run `systemctl enable wl-quick@wg0 && systemctl start wl-quick@wg0`. In the
future, the `wirelink` instance will automatically start & stop along with the
`wg-quick` instance.

`wirelink@.service` is provided for more manual configurations, such as if you
configure your wireguard interface in `/etc/network/interfaces`. Enable and
start it with e.g. `systemctl enable wirelink@wg0 && systemctl start wirelink@wg0`
similar to how `wl-quick@` works. If the wireguard interface goes down, the
service will fail, but it is configured to auto-restart periodically until the
link comes back up.

## How It Works

Peers produce a list of local "facts" based on information from the
wireguard device and the local network interfaces.  Facts have:

* A subject
  * Who is the fact about
* An attribute
  * What attribute of the subject does the fact describe
* A value
  * What is the value of that attribute
* A TTL
  * For how long should this fact be considered valid

For now subjects are always a peer's public key. Attributes are the peer's
allowed ip value(s) and possible endpoints. Peers share endpoints of other
peers if they have a live connection to that peer. Peers also share all their
local IP addresses and their listening port in case they are on a public IP or
other peers are on the same LAN.

Peers periodically send all their locally known facts to all the other peers,
along with a generic placeholder "I'm here" fact that is used to detect link
health. What facts are sent when is filtered to avoid sending facts they think
the other peer already knows and is not going to forget before the next send
time comes around.

Peers receive facts from other peers as they arrive, but filter them based on a
trust model. For now trust is simple:

* Peers are trusted to provide possible endpoints for themselves
* Peers are trusted to provide possible endpoints for other peers
* Peers that have an allowed ip value that implies they route packets for the
  network are trusted to provide AllowedIP values for other peers
* Currently nobody is trusted to provide information on new peers, i.e. all
  peers must have an externally configured list of the other peer public keys
  with which they are willing to communicate.
  * There are hooks in place to add this trust level in the future, but they
    are not yet implemented

Received facts are removed as they expire based on the given TTL value, or
renewed as fresh versions come in from trusted sources.

## Connecting two peers

To connect two peers that aren't directly connected, each end (independently)
configures the remote peer in the local wireguard interface with that peer's
automatic link local address. It then cycles through the known endpoints and
attempts to contact the peer. This should work with simple NATs, but may fail
for more complex ones where a full STUN/ICE system would succeed, esp. since
there is no coordination on which endpoints are being tried when.

If contact is successful, then the peers other allowed IPs are added and
traffic can start to flow directly.

Once a live connection is established, it is monitored to see if it stays
alive. If it goes down, and the local peer is not a router, then the allowed
IPs other than the automatic link-local one are removed, so that traffic to
that peer will be routed through a central router peer, and attempts to connect
to that peer directly will resume. The removal of allowed IPs is not done for
router nodes since they are the source of that information, and removing them
from the router node would cause the network to forget that, and also obstruct
that peer from reconnecting to the network.

### Contact Detection

Determining when there is a live connection to a peer is based on two things:

* Does the wireguard interface report a recent handshake?
  * Recent is defined based on a combination of timeout values from the
    wireguard go implementation.
* Have we received an "I'm here" fact packet from the peer recently.

## Inspiration

A couple key items from upstream inspired this:

* Automatic assigning of link-local IPv6 addresses:
  https://lists.zx2c4.com/pipermail/wireguard/2017-April/001177.html
  (and following messages, about the `wg set wg0 llv6 on` proposal)
* The NAT hole-punching example that ships with the wireguard source:
  https://git.zx2c4.com/WireGuard/tree/contrib/examples/nat-hole-punching
