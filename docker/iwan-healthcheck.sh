#!/bin/sh
set -eu

IWAN_TUN="${IWAN_TUN:-iwan0}"
IWAN_HEALTHCHECK_URL="${IWAN_HEALTHCHECK_URL:-http://www.gstatic.com/generate_204}"
IWAN_HEALTHCHECK_TIMEOUT="${IWAN_HEALTHCHECK_TIMEOUT:-1}"

has_process() {
    name="$1"
    for comm in /proc/[0-9]*/comm; do
        [ -r "$comm" ] || continue
        [ "$(cat "$comm")" = "$name" ] && return 0
    done
    return 1
}

listens_on() {
    port="$1"
    ss -ltn | grep -Eq "[.:]${port}[[:space:]]"
}

has_process iwan-client-oid || {
    echo "iwan-client-oidc is not running" >&2
    exit 1
}

has_process 3proxy || {
    echo "3proxy is not running" >&2
    exit 1
}

ip -4 addr show dev "$IWAN_TUN" 2>/dev/null | grep -q 'inet ' || {
    echo "$IWAN_TUN has no IPv4 address" >&2
    exit 1
}

ip route show default dev "$IWAN_TUN" | grep -q '^default ' || {
    echo "default route does not use $IWAN_TUN" >&2
    exit 1
}

listens_on 1080 || {
    echo "SOCKS5 port 1080 is not listening" >&2
    exit 1
}

listens_on 8888 || {
    echo "HTTP proxy port 8888 is not listening" >&2
    exit 1
}

check_url_with_proxy() {
    name="$1"
    proxy="$2"

    output="$(curl -fsS --max-time "$IWAN_HEALTHCHECK_TIMEOUT" --proxy "$proxy" "$IWAN_HEALTHCHECK_URL" 2>&1)" || {
        echo "$name proxy cannot access $IWAN_HEALTHCHECK_URL via $proxy" >&2
        echo "$output" >&2
        return 1
    }
}

failed=0

check_url_with_proxy "HTTP" "http://127.0.0.1:8888" || failed=1
check_url_with_proxy "SOCKS5" "socks5h://127.0.0.1:1080" || failed=1

exit "$failed"
