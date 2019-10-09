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
