# TODO

## Endpoint Selection

* Prefer RFC1918 addresses that match a local interface over those that
  don't. TBD exactly what "prefer" means outside the first set of attempts.

## Router Detection

* Check the local interface's configured IP addresses against the peers'
  AllowedIPs. If nobody has an AllowedIP that overlaps our local IP, then we
  are probably a router.
  * This could change dynamically in theory as we receive AIP info from other
    peers, but that could only happen in practice if we have a p-t-p link to
    another non-router peer, otherwise there's no way for us to receive anything.

## Packaging

* pre/post inst/rm scripts for systemd service
* Release script

## Systemd Integration

* `sd_notify`
* Template unit
  * Tied to `wg-quick`?
  * Variant with and without?

## Functionality

* Handle wireguard interface shutdown gracefully
* Real logging, not `Printf`
  * Error reporting, esp. instead of `panic`
  * Verbosity levels
* Allow env vars to set cli args to make local overrides of systemd unit easy (e.g. to force router mode)
* CLI/ENV args to control which interfaces to report for local endpoints
* Faster AIP config when receiving the first ping fact from a peer
  * Check received ping facts against `peerAlive`, if new force ending the current receive chunk?
* Intelligent prioritizaiton of peer EPs to try
  * EPs that are on a local subnet, then EPs on the internet, then everything else?
  * Implement via LRU penalty?

## Security

* Drop privileges after startup
  * Close the netlink socket for local interface config when we don't need it any more
  * Verify `wgctrl` keeps the netlink socket open so that this isn't an issue
* Improved trust models
  * Peer trust level override (e.g. to set `AddPeer`)
* Implement `AddPeer` trust level

## Fancy

* Use `pcap` or the like to detect when we are actually trying to talk to a peer
  * Use this to only do peer setup when we need it

### Reduced Chatter

* Longer fact TTLs
* Send to non-routers less
  * Option to disable all p2p chatter except liveness, only send facts to router?
  * Need to be careful not to leave a peer in a dead setup (instead of resetting AllowedIPs)
* Tell routers who we want to talk to (a peer-valued fact)
  * Only tell leaves info about peers they want
* Multi-fact packets
  * How to find out path MTU to avoid fragmentation?
