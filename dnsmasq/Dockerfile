FROM alpine:latest

ENV METADATA_FILE=/data/meta.json
ENV UNPACKED_ISO_DIR=/data/unpacked-iso

VOLUME /data/unpacked-iso

COPY entrypoint.sh /entrypoint.sh

# Install required packages
RUN apk add --no-cache \
        dnsmasq \
        grub-efi \
        iproute2 \
        jq \
        libcap && \
    /usr/sbin/setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=+ep' /usr/sbin/dnsmasq && \
    mkdir -p /var/lib/tftpboot /etc/dnsmasq.d /var/lib/dnsmasq && \
    chown -R dnsmasq:dnsmasq /var/lib/tftpboot /etc/dnsmasq.d /var/lib/dnsmasq && \
    chmod +x /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s CMD pgrep dnsmasq || exit 1

USER dnsmasq

ENTRYPOINT ["/entrypoint.sh"]
CMD ["dnsmasq"]


