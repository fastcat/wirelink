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

* Better pre/post inst/rm scripts for systemd service
* Release script
* ChangeLog generation
* Auto-tag and release from CI

## Systemd Integration

* `sd_notify`

## Functionality

* Don't activate AIP config until we think the peer will reciprocate
* Intelligent prioritization of peer EPs to try
  * EPs that are on a local subnet, then EPs on the internet, then everything else?
  * Implement via LRU penalty?
* Option to de-configure at exit for leaves
  * i.e. reset wireguard config to as if every peer was unhealthy, only talk to routers,
    or even just remove all non-router peers
* Fix problems with peer deletion due to not having detected trust source went offline
  * The problem is that the last facts can expire before we realize the trust source is gone
  * Probably need hysteresis on the delete decision: don't delete the peer until we've thought it was
    deletable for a full fact TTL
  * AIP removal feature fixed some bugs here, may not be an issue any more
* Improved detection of local facts to trust / transmit
  * `AllowedIPs` is assumed to be the whole subnet, which would be bad in more complex configurations
    * Being able to list `AllowedIPs` in the config file may be enough to avoid this
  * Only trust sources should trust the local AIP settings for peers, but
    trust sources might not _know_ they are trusted
    * Again, requiring configuration may be enough for this

## Security

* Drop privileges after startup
  * Close the netlink socket for local interface config when we don't need it any more
  * This is obstructed by Go's lack of support:
    [golang/go#1435](https://github.com/golang/go/issues/1435)
  * Worked around for now by having systemd units drop privileges
* Trust delegation (i.e. implement `SetTrust` level)
* Improved trust models

## Fancy

* Use packet capture to detect when we are actually trying to talk to a peer
  * Use this to only do peer setup when we need it

### Chatter Management

* Tell routers who we want to talk to (a peer-valued fact)
  * Only tell leaves info about peers they want
  * Or by IP address (see packet capture): only enable local peers that we want
    to talk to or who want to talk to us

### Config

* Allow configuring various parameters
  * `MaxChunk`
  * `ChunkPeriod`
  * `AlivePeriod`
  * `FactTTL`
  * listen port / offset
    * This one is a bit tricky as it needs to be consistent across the network for now
    * With signed facts, could have a fact for the fact port,
      though deciding among multiple values could get weird
* Allow configuring `AllowedIPs` in config file
  * With this we can get close to completely owning the wireguard config on leaves,
    and owning most of it on routers and trust sources
