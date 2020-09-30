#!/bin/sh
if ! which dlv ; then
	export PATH="${GOPATH}/bin:$PATH"
fi
if [ "$WIRELINK_DEBUG_AS_ROOT" = "true" ]; then
	# sudo may not obey "our" $PATH, so need to look up the binary ourselves
	exec sudo "$(which dlv)" --only-same-user=false "$@"
else
	exec dlv "$@"
fi
