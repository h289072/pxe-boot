#!/bin/bash
set -euo pipefail

# Paths
TFTP_DIR="/tftpboot"
CONFIG_DIR="/config"
IMAGES_DIR="/images"

# Generate GRUB config from meta.json
if [ -f "$IMAGES_DIR/meta.json" ]; then
    echo "Generating GRUB config..."
    jq -r '
      .images[] | "menuentry \"" + .id + "\" {\n  linux " + .boot_info.kernel_path +
      (if .boot_info.kernel_options then
         " " + (.boot_info.kernel_options | to_entries | map("\(.key)=\(.value)") | join(" "))
       else "" end) + 
      "\n  initrd " + .boot_info.initrd_path + "\n  boot\n}"
    ' "$IMAGES_DIR/meta.json" > "$TFTP_DIR/grub.cfg"
else
    echo "No meta.json found."
fi

# Generate GRUB bootloader
grub-mknetdir --net-directory="$TFTP_DIR"

# Start dnsmasq (TFTP + DHCP)
exec dnsmasq --no-daemon \
    --enable-tftp \
    --tftp-root="$TFTP_DIR" \
    --dhcp-range=192.168.0.100,192.168.0.200,12h \
    --dhcp-boot=grubnetx64.efi \
    --log-dhcp
