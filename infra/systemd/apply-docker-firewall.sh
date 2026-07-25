#!/bin/sh
set -eu

chain=CODEX-MOBILE
input_chain=CODEX-MOBILE-INPUT

remove_rules() {
  while /usr/sbin/iptables --wait -C DOCKER-USER -j "$chain" 2>/dev/null; do
    /usr/sbin/iptables --wait -D DOCKER-USER -j "$chain"
  done
  /usr/sbin/iptables --wait -F "$chain" 2>/dev/null || true
  /usr/sbin/iptables --wait -X "$chain" 2>/dev/null || true
  while /usr/sbin/iptables --wait -C INPUT -j "$input_chain" 2>/dev/null; do
    /usr/sbin/iptables --wait -D INPUT -j "$input_chain"
  done
  /usr/sbin/iptables --wait -F "$input_chain" 2>/dev/null || true
  /usr/sbin/iptables --wait -X "$input_chain" 2>/dev/null || true
}

if [ "${1:-}" = --remove ]; then
  remove_rules
  exit 0
fi

case "${CODER_BIND_PORT:-}" in
  ''|*[!0-9]*) echo "CODER_BIND_PORT must be numeric" >&2; exit 1 ;;
esac
if [ "$CODER_BIND_PORT" -lt 1 ] || [ "$CODER_BIND_PORT" -gt 65535 ]; then
  echo "CODER_BIND_PORT is outside the valid range" >&2
  exit 1
fi
case "${CODER_BIND_ADDRESS:-}" in
  ''|*[!0-9.]*) echo "CODER_BIND_ADDRESS must be a literal IPv4 address" >&2; exit 1 ;;
esac
case "${WORKSPACE_CONTROL_SUBNET:-}" in
  ''|*[!0-9./]*) echo "WORKSPACE_CONTROL_SUBNET must be a literal IPv4 CIDR" >&2; exit 1 ;;
esac
/usr/bin/python3 - "$CODER_BIND_ADDRESS" "$WORKSPACE_CONTROL_SUBNET" <<'PY'
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
network = ipaddress.ip_network(sys.argv[2], strict=True)
private = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
if not isinstance(address, ipaddress.IPv4Address) or not any(
    address in item for item in private
):
    raise SystemExit("CODER_BIND_ADDRESS must be an RFC1918 IPv4 address")
if not isinstance(network, ipaddress.IPv4Network) or not any(
    network.subnet_of(item) for item in private
):
    raise SystemExit("WORKSPACE_CONTROL_SUBNET must be an RFC1918 IPv4 network")
if not 24 <= network.prefixlen <= 28:
    raise SystemExit("WORKSPACE_CONTROL_SUBNET prefix must be between /24 and /28")
if address in network:
    raise SystemExit("WORKSPACE_CONTROL_SUBNET must not contain CODER_BIND_ADDRESS")
PY

# Docker creates DOCKER-USER before evaluating published-port forwarding. A
# dedicated child chain avoids resetting any operator rules already present.
/usr/sbin/iptables --wait -N "$chain" 2>/dev/null || true
/usr/sbin/iptables --wait -F "$chain"
/usr/sbin/iptables --wait -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# Only the private Compose bridge may reach internal service ports through the
# forwarding path. The edge bridge gets only the public proxy's control-plane
# destination, not Coder, PostgreSQL, or an admin/metrics listener.
/usr/sbin/iptables --wait -A "$chain" -i cm-data0 -j RETURN
/usr/sbin/iptables --wait -A "$chain" -i cm-edge0 -p tcp --dport 8080 -j RETURN
/usr/sbin/iptables --wait -A "$chain" -i cm-control0 -s "$WORKSPACE_CONTROL_SUBNET" \
  -d "$CODER_BIND_ADDRESS" -p tcp --dport "$CODER_BIND_PORT" -j RETURN
/usr/sbin/iptables --wait -A "$chain" -i cm-control0 -j DROP
for port in 2019 2112 2113 5432 8080 "$CODER_BIND_PORT"; do
  /usr/sbin/iptables --wait -A "$chain" -p tcp --dport "$port" -j DROP
done
/usr/sbin/iptables --wait -A "$chain" -j RETURN
/usr/sbin/iptables --wait -C DOCKER-USER -j "$chain" 2>/dev/null \
  || /usr/sbin/iptables --wait -I DOCKER-USER 1 -j "$chain"

# Traffic addressed to a host listener traverses INPUT, not DOCKER-USER. Only
# the host itself and immutable relays may use the private Coder listener.
/usr/sbin/iptables --wait -N "$input_chain" 2>/dev/null || true
/usr/sbin/iptables --wait -F "$input_chain"
/usr/sbin/iptables --wait -A "$input_chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
/usr/sbin/iptables --wait -A "$input_chain" -i lo -j RETURN
/usr/sbin/iptables --wait -A "$input_chain" -i cm-control0 -s "$WORKSPACE_CONTROL_SUBNET" \
  -d "$CODER_BIND_ADDRESS" -p tcp --dport "$CODER_BIND_PORT" -j RETURN
for port in 2019 2112 2113 5432 8080 "$CODER_BIND_PORT"; do
  /usr/sbin/iptables --wait -A "$input_chain" -p tcp --dport "$port" -j DROP
done
/usr/sbin/iptables --wait -A "$input_chain" -i cm-control0 -j DROP
/usr/sbin/iptables --wait -A "$input_chain" -j RETURN
/usr/sbin/iptables --wait -C INPUT -j "$input_chain" 2>/dev/null \
  || /usr/sbin/iptables --wait -I INPUT 1 -j "$input_chain"
