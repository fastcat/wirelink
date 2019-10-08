# TODO

## Endpoint Selection

* Prefer RFC1918 addresses that match a local interface over those that
  don't. TBD exactly what "prefer" means outside the first set of attempts.

## Peer Configuration

* Don't configure `AllowedIPs` until we know the other peer is going to
  reciprocate.
  
  * Check peer knowledge for these values? That won't work right in curent form
    because we assume peer knows things we sent it, but we don't know if it
    actually received them. Could have peer go live at crypto layer without
    `wirelink` running.
  * Use a null fact (`Attribute = 0`) as an "I'm here" which we only track in
    peer knowledge state based on receiving it? Don't configure AIPs on a peer
    unless this is live, but don't deconfigure them if it is dead.
