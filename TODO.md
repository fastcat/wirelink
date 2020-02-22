# TODO

## Packaging

* Better pre/post inst/rm scripts for systemd service
  * Upgrading `wireguard` often leaves `wirelink` inactive
* ChangeLog generation
* Auto-tag and release from CI

## Systemd Integration

* `sd_notify`

## Functionality

* Synchronize activation of AIPs with peer
  * Send a special fact when adding AIPs, which triggers the remote end to
    process queued facts immediately, which should trigger that peer to also
    add AIPs if it didn't already.
* Intelligent prioritization of peer EPs to try
  * EPs that are on a local subnet, then EPs on the internet, then
    everything else?
  * Mechanism? LRU penalty / bonus? I.e. add N ms to actual LU stamp for
    internet EPs, and M>n for non-matching LAN IPs?
* Router detection: Inspect the `AllowedIP` facts other peers send about
  ourselves (need to change `broadcastFacts` so they send those to us)
* Adjust fact sending and TTL behavior so that alive facts reliably expire
  before other facts, avoiding inconsistent behavior around trust and link
  resets.

## Security

* Drop privileges after startup
  * This is obstructed by Go's lack of support:
    [golang/go#1435](https://github.com/golang/go/issues/1435)
  * Worked around for now by having systemd units drop privileges
* Trust delegation (i.e. implement `SetTrust` level)
* Improved trust models
  * E.g. require a majority of trust sources to agree before adding a peer
    (`Membership` in this mode gets a bit more complicated)
  * Conflating router status with trust levels is getting confusing, consider
    removing this, or having it be a separate trust model from the config,
    and which is enabled is part of the config

## Fancy

* Use packet capture to detect when we are actually trying to talk to a peer
  * Use this to only do peer setup when we need it
* Delete peers that are offline
  * E.g. by not broadcasting facts about if if it's unhealthy

### Chatter Management

* Tell routers who we want to talk to (a peer-valued fact)
  * Only tell leaves info about peers they want
  * Or by IP address (see packet capture): only enable local peers that we
    want to talk to or who want to talk to us (requires fact exchange about
    who we want to talk to so the remote end will add us)

### Config

* Allow configuring various parameters
  * `MaxChunk`, `ChunkPeriod`, `AlivePeriod`, `FactTTL`, port / offset
  * All of these are a bit tricky as they mostly need to be consistent
    across the network for things to work well (or in the case of the port,
    at all)
  * Some internal capability for this is present now to support time
    acceleration in tests, but it is not yet configurable.
* Better logger, at least add some basic filtering support for debug mode
