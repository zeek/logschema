#! /usr/bin/env bash
#
# Run with the "oldzeek" alternative when we find Zeek older than 6.0, otherwise
# run as usual. This may need to become more fine-grained for older versions in
# the future.

ALTERNATIVE=

if command -v zeek-config >/dev/null; then
    if zeek-config --version | grep -q '^[12345]\.'; then
        ALTERNATIVE="-a oldzeek"
    fi
fi

btest $ALTERNATIVE "$@"
