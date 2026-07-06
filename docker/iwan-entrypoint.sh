#!/bin/sh
set -eu

CONFIG_DIR="${IWAN_CONFIG_DIR:-/config}"
SERVER_INDEX_FILE="${IWAN_SERVER_INDEX_FILE:-${CONFIG_DIR}/server_index}"
IWAN_TUN="${IWAN_TUN:-iwan0}"
IWAN_SERVER_INDEX="${IWAN_SERVER_INDEX:-}"
IWAN_PROXY_CIDR="${IWAN_PROXY_CIDR:-0.0.0.0/0}"
IWAN_PROXY_IP="${IWAN_PROXY_IP:-}"
IWAN_PROXY_DOMAIN="${IWAN_PROXY_DOMAIN:-}"
IWAN_ENCRYPT="${IWAN_ENCRYPT:-1}"
THREEPROXY_CONFIG="${THREEPROXY_CONFIG:-/etc/3proxy/3proxy.cfg}"

mode="auto"
iwan_pid=""
proxy_pid=""
EXTRA_ARGS=""

if [ "$#" -gt 0 ]; then
    case "$1" in
        --fetch) mode="fetch"; shift ;;
        --list) mode="list"; shift ;;
        --connect) mode="connect"; shift ;;
        --auto) mode="auto"; shift ;;
        fetch|list|connect|auto) mode="$1"; shift ;;
        *) mode="command" ;;
    esac
fi

EXTRA_ARGS="$*"

run_simple_mode() {
    case "$mode" in
        fetch)
            exec iwan-client-oidc --config-dir "$CONFIG_DIR" --fetch "$@"
            ;;
        list)
            exec iwan-client-oidc --config-dir "$CONFIG_DIR" --list "$@"
            ;;
        command)
            exec "$@"
            ;;
    esac
}

ensure_config() {
    if [ -s "$CONFIG_DIR/servers.json" ]; then
        return
    fi

    if [ "$mode" = "auto" ]; then
        echo "missing $CONFIG_DIR/servers.json; starting OIDC login" >&2
        iwan-client-oidc --config-dir "$CONFIG_DIR" --fetch
    fi

    if [ ! -s "$CONFIG_DIR/servers.json" ]; then
        echo "missing $CONFIG_DIR/servers.json; start this container interactively once" >&2
        exit 1
    fi
}

choose_server() {
    if [ -n "$IWAN_SERVER_INDEX" ]; then
        server_index="$IWAN_SERVER_INDEX"
    elif [ -s "$SERVER_INDEX_FILE" ]; then
        server_index="$(tr -cd '0-9' < "$SERVER_INDEX_FILE")"
    else
        iwan-client-oidc --config-dir "$CONFIG_DIR" --list
        printf '  Select server to save for this container: '
        read -r server_index
        server_index="$(printf '%s' "$server_index" | tr -cd '0-9')"
        [ -n "$server_index" ] || {
            echo "invalid server selection" >&2
            exit 1
        }
        printf '%s\n' "$server_index" > "$SERVER_INDEX_FILE"
    fi

    if [ -z "$server_index" ]; then
        echo "empty server selection; remove $SERVER_INDEX_FILE and start interactively again" >&2
        exit 1
    fi
}

build_iwan_command() {
    set -- iwan-client-oidc \
        --config-dir "$CONFIG_DIR" \
        --connect \
        --tun "$IWAN_TUN" \
        --encrypt "$IWAN_ENCRYPT"

    [ -n "$IWAN_PROXY_CIDR" ] && set -- "$@" --proxy-cidr "$IWAN_PROXY_CIDR"
    [ -n "$IWAN_PROXY_IP" ] && set -- "$@" --proxy-ip "$IWAN_PROXY_IP"
    [ -n "$IWAN_PROXY_DOMAIN" ] && set -- "$@" --proxy-domain "$IWAN_PROXY_DOMAIN"

    IWAN_COMMAND="$*"
}

start_iwan() {
    build_iwan_command
    # IWAN_COMMAND and EXTRA_ARGS are simple CLI fragments controlled by env vars.
    printf '%s\n' "$server_index" | sh -c 'exec "$@"' sh $IWAN_COMMAND $EXTRA_ARGS &
    iwan_pid="$!"
}

wait_for_tun() {
    for _ in $(seq 1 60); do
        if ! kill -0 "$iwan_pid" 2>/dev/null; then
            wait "$iwan_pid"
            exit $?
        fi
        if ip -4 addr show dev "$IWAN_TUN" 2>/dev/null | grep -q 'inet '; then
            return
        fi
        sleep 1
    done

    echo "timed out waiting for $IWAN_TUN to become ready" >&2
    cleanup
    exit 1
}

start_proxy() {
    3proxy "$THREEPROXY_CONFIG" &
    proxy_pid="$!"
}

monitor_processes() {
    while true; do
        if ! kill -0 "$iwan_pid" 2>/dev/null; then
            wait "$iwan_pid"
            exit $?
        fi
        if ! kill -0 "$proxy_pid" 2>/dev/null; then
            wait "$proxy_pid"
            exit $?
        fi
        sleep 2
    done
}

cleanup() {
    [ -z "$proxy_pid" ] || kill "$proxy_pid" 2>/dev/null || true
    [ -z "$iwan_pid" ] || kill "$iwan_pid" 2>/dev/null || true
}

trap cleanup INT TERM

run_simple_mode "$@"
ensure_config
choose_server
start_iwan
wait_for_tun
start_proxy
monitor_processes
