#!/usr/bin/env sh

set -eu

# Defaults (werden ggf. überschrieben)
LIGHTTP_CONF_DEFAULT="/etc/lighttpd/lighttpd.conf"
METADATA_FILE_DEFAULT="/data/meta.json"
UNPACKED_ISO_DIR_DEFAULT="/data/unpacked-iso"

# Netzwerkdaten ermitteln
IFACE_DEFAULT=$(ip route get 8.8.8.8 | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

# Konfigurierbare Variablen, per CLI oder ENV
for arg in "$@"; do
  case "$arg" in
    LIGHTTP_CONF=*|METADATA_FILE=*|UNPACKED_ISO_DIR=*|IFACE=*|IP=*)
      eval "$arg"
      ;;
    *)
      CMD="$@"
      break
      ;;
  esac
done

# Werte mit Priorität: CLI > ENV > Default
LIGHTTP_CONF="${LIGHTTP_CONF:-${LIGHTTP_CONF_DEFAULT}}"
METADATA_FILE="${METADATA_FILE:-${METADATA_FILE_DEFAULT}}"
UNPACKED_ISO_DIR="${UNPACKED_ISO_DIR:-${UNPACKED_ISO_DIR_DEFAULT}}"
IFACE="${IFACE:-${IFACE_DEFAULT}}"

# Alle CIDRs für das Interface sammeln (eine pro Zeile)
IP_CIDRS=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}')

# # Wenn IP nicht per CLI/ENV gesetzt wurde, nimm die erste CIDR und extrahiere IP
if [ -z "${IP:-}" ]; then
  IP=$(printf "%s\n" "$IP_CIDRS" | head -n1 | cut -d/ -f1)
fi

cat > "$LIGHTTP_CONF_DEFAULT" <<EOF
server.document-root = "${UNPACKED_ISO_DIR}"
server.bind = "${IP}"
server.port = 8080
server.username = "lighttpd"
server.groupname = "lighttpd"
server.pid-file = ""

dir-listing.activate = "enable"

server.modules = (
  "mod_dirlisting",
  "mod_accesslog"
)

accesslog.filename = "/dev/fd/3"
server.errorlog = "/dev/stderr"
EOF

echo "[INFO] Starting lighttpd with:"
echo "$@"

exec "$@"