#!/usr/bin/env sh

set -eu

# Defaults (werden ggf. überschrieben)
TFTP_DIR_DEFAULT="/var/lib/tftpboot"
DNSMASQ_CONF_DEFAULT="/etc/dnsmasq.d/pxe.conf"
METADATA_FILE_DEFAULT="/data/meta.json"
UNPACKED_ISO_DIR_DEFAULT="/data/unpacked-iso"

# Netzwerkdaten ermitteln
IFACE_DEFAULT=$(ip route get 8.8.8.8 | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

# Konfigurierbare Variablen, per CLI oder ENV
for arg in "$@"; do
  case "$arg" in
    TFTP_DIR=*|DNSMASQ_CONF=*|METADATA_FILE=*|UNPACKED_ISO_DIR=*|IFACE=*|IP=*)
      eval "$arg"
      ;;
    *)
      CMD="$@"
      break
      ;;
  esac
done

# Werte mit Priorität: CLI > ENV > Default
TFTP_DIR="${TFTP_DIR:-${TFTP_DIR_DEFAULT}}"
DNSMASQ_CONF="${DNSMASQ_CONF:-${DNSMASQ_CONF_DEFAULT}}"
METADATA_FILE="${METADATA_FILE:-${METADATA_FILE_DEFAULT}}"
UNPACKED_ISO_DIR="${UNPACKED_ISO_DIR:-${UNPACKED_ISO_DIR_DEFAULT}}"
IFACE="${IFACE:-${IFACE_DEFAULT}}"

IPXE_CONFIG="${UNPACKED_ISO_DIR}/boot.ipxe"

# Alle CIDRs für das Interface sammeln (eine pro Zeile)
IP_CIDRS=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}')

# # Wenn IP nicht per CLI/ENV gesetzt wurde, nimm die erste CIDR und extrahiere IP
if [ -z "${IP:-}" ]; then
  IP=$(printf "%s\n" "$IP_CIDRS" | head -n1 | cut -d/ -f1)
fi

# Passende CIDR zur IP finden
IP_CIDR=""
while read -r cidr; do
  ip_part=$(printf "%s" "$cidr" | cut -d/ -f1)
  if [ "$ip_part" = "$IP" ]; then
    IP_CIDR="$cidr"
    break
  fi
done <<EOF
$IP_CIDRS
EOF

# Falls nicht gefunden (sollte nie passieren), Fehler
if [ -z "$IP_CIDR" ]; then
  echo "Could not find network CIDR for IP $IP" >&2
  exit 1
fi

# Netzwerkdaten berechnen
NETWORK=$(ipcalc -n "$IP_CIDR" | awk -F= '/^NETWORK=/{print $2}')
NETMASK=$(ipcalc -m "$IP_CIDR" | awk -F= '/^NETMASK=/{print $2}')

cat > "$DNSMASQ_CONF" <<EOF
no-daemon
interface=$IFACE
bind-interfaces
port=0
dhcp-range=$NETWORK,proxy,$NETMASK
enable-tftp
tftp-root=$TFTP_DIR

# PXE boot for UEFI x86_64
dhcp-match=set:efi-x86_64,option:client-arch,7

# PXE für UEFI x86_64 Client
pxe-service=tag:!ipxe,X86-64_EFI,"PXE Boot",ipxe.efi

# Optional: iPXE-Erkennung → HTTP
dhcp-userclass=set:ipxe,iPXE
dhcp-boot=tag:ipxe,http://${IP}:8080/boot.ipxe

dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases
log-facility=-
log-queries
log-dhcp
EOF

IPXE_MENU=""
IPXE_TARGETS=""
# Iterate over each image in the JSON file to assemble iPXE config
while IFS= read -r image; do
    # Extract image ID
    ID=$(printf "%s" "$image" | jq -r '.id')

    echo "Processing image $ID"

    # Extract boot information
    KERNEL_PATH=$(printf "%s" "$image" | jq -r '.boot_info.kernel_path')
    INITRD_PATH=$(printf "%s" "$image" | jq -r '.boot_info.initrd_path')

    # Construct full paths for kernel and initrd
    FULL_KERNEL_PATH="/${ID}${KERNEL_PATH}"
    FULL_INITRD_PATH="/${ID}${INITRD_PATH}"

    echo "Kernel path: ${UNPACKED_ISO_DIR}${FULL_KERNEL_PATH}"
    echo "Initrd path: ${UNPACKED_ISO_DIR}${FULL_INITRD_PATH}"

    if [ -f "${UNPACKED_ISO_DIR}${FULL_KERNEL_PATH}" ] && [ -f "${UNPACKED_ISO_DIR}${FULL_INITRD_PATH}" ]; then
        # Extract kernel options and construct the options string
        KERNEL_OPTIONS=$(printf "%s" "$image" | jq -r '
        .boot_info.kernel_options? // [] | .[]' | paste -sd ' ' -)

        DESCRIPTION=$(printf "%s" "$image" | jq -r '.boot_info.description')

        echo "Kernel files found, registering $DESCRIPTION"

        # Replace $IP placeholder in kernel options
        OS_URL="http://${IP}:8080/${ID}"
        KERNEL_OPTIONS=${KERNEL_OPTIONS//\$BASE_URL/$OS_URL}

        # Assemble iPXE menu entries
        IPXE_MENU="$(printf "%s\nitem %s %s" "$IPXE_MENU" "$ID" "$DESCRIPTION")"

        # Assemble iPXE targets
        IPXE_TARGETS="$(printf "%s\n:%s\nkernel http://%s:8080%s %s\ninitrd http://%s:8080%s\nboot\n\n\n" \
          "$IPXE_TARGETS" "$ID" "$IP" "$FULL_KERNEL_PATH" "$KERNEL_OPTIONS" "$IP" "$FULL_INITRD_PATH")"
    fi
done <<EOF
$(jq -c '.images[]' "$METADATA_FILE")
EOF


# This file will be used be hosted by lighttpd
cat <<EOF > "$IPXE_CONFIG"
#!ipxe

# Auto-generated iPXE configuration

menu iPXE Boot Menu
item local Boot from local disk
item shell iPXE Shell$IPXE_MENU
choose --default local --timeout 5000 target && goto \${target}

:local
exit

:shell
shell
$IPXE_TARGETS
EOF

echo "[INFO] Starting dnsmasq with:"
echo "$@"

exec "$@"