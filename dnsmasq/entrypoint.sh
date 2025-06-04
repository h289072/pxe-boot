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

GRUB_CONFIG="${TFTP_DIR}/grub.cfg"

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
pxe-service=tag:efi-x86_64,x86-64_EFI,"Network Boot",grubx64.efi
dhcp-match=set:efi-x86_64,option:client-arch,7
dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases
log-facility=-
log-queries
log-dhcp
EOF

# Generate GRUB bootloader
grub-mkimage -p "(tftp,$IP)" -O x86_64-efi -o "${TFTP_DIR}/grubx64.efi" \
	tftp http net linux normal configfile efinet echo

# Start the GRUB configuration file
cat <<EOF > "$GRUB_CONFIG"
# Auto-generated GRUB configuration

set default=0
set timeout=5

menuentry "Boot from local disk" {
    set root=(hd0)
    chainloader +1
    boot
}

EOF

# Iterate over each image in the JSON file
jq -c '.images[]' "$METADATA_FILE" | while read -r image; do
    # Extract image ID
    ID=$(printf "%s" "$image" | jq -r '.id')

    # Extract boot information
    KERNEL_PATH=$(printf "%s" "$image" | jq -r '.boot_info.kernel_path')
    INITRD_PATH=$(printf "%s" "$image" | jq -r '.boot_info.initrd_path')

    # Construct full paths for kernel and initrd
    FULL_KERNEL_PATH="/${ID}${KERNEL_PATH}"
    FULL_INITRD_PATH="/${ID}${INITRD_PATH}"

    if [ -f "$UNPACKED_ISO_DIR/$FULL_KERNEL_PATH" ] && [ -f "$UNPACKED_ISO_DIR/$FULL_INITRD_PATH" ]; then
        # Extract kernel options and construct the options string
        KERNEL_OPTIONS=$(printf "%s" "$image" | jq -r '
        .boot_info.kernel_options? // [] | .[]' | paste -sd ' ' -)

        DESCRIPTION=$(printf "%s" "$image" | jq -r '.boot_info.description')

        # Replace $IP placeholder in kernel options
        OS_URL="http://${IP}:8080/${ID}"
        KERNEL_OPTIONS=${KERNEL_OPTIONS//\$BASE_URL/$OS_URL}

        # Append the menu entry to the GRUB configuration file
        cat <<EOF >> "$GRUB_CONFIG"
menuentry "$DESCRIPTION via network boot" {
    set root=(http,$IP:8080)
    linux $FULL_KERNEL_PATH $KERNEL_OPTIONS
    initrd $FULL_INITRD_PATH
    boot
}
EOF


        echo "" >> "$GRUB_CONFIG"
    fi
done

echo "[INFO] Starting dnsmasq with:"
echo "$@"

exec "$@"