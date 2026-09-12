#!/bin/sh
set -euo pipefail

PORT="${DNS_PROBE_PORT:-5335}"
SERVERS="${DNS_PROBE_SERVERS:-127.0.0.1 10.100.0.3}"
DOMAINS="${DNS_PROBE_DOMAINS:-www.apple.com apps.apple.com mesu.apple.com swcdn.apple.com www.akamai.com cloudflare.com}"
QTYPES="${DNS_PROBE_QTYPES:-A AAAA HTTPS SVCB}"

for server in $SERVERS; do
    for domain in $DOMAINS; do
        for qtype in $QTYPES; do
            printf '\nVIEW=%s DOMAIN=%s TYPE=%s\n' "$server" "$domain" "$qtype"
            dig @"$server" -p "$PORT" "$domain" "$qtype" \
                +time=4 +tries=1 +nocmd +noquestion +nocomments +nostats
        done
    done
done
