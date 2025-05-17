FROM cgr.dev/chainguard/wolfi-base AS base

# Install required packages
RUN apk update && apk add --no-cache \
    dnsmasq \
    grub \
    grub-efi \
    jq

RUN setcap 'cap_net_bind_service=+ep' /usr/sbin/dnsmasq

# Create directories for TFTP and GRUB
RUN mkdir -p /var/lib/tftpboot /etc/dnsmasq.d

# Copy dnsmasq configuration
COPY configs/dnsmasq.conf /etc/dnsmasq.conf

# Create working dirs
RUN mkdir -p /tftpboot /config && \
    chown -R nonroot:nonroot /tftpboot /images /config

USER nonroot

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
