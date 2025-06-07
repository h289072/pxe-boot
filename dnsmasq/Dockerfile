FROM alpine:latest

ENV METADATA_FILE=/data/meta.json
ENV UNPACKED_ISO_DIR=/data/unpacked-iso

VOLUME /data/unpacked-iso

COPY entrypoint.sh /entrypoint.sh

# Install required packages
RUN apk add --no-cache \
        dnsmasq \
        iproute2 \
        jq \
        libcap \
        shadow && \
    addgroup -g 10000 pxeboot && \
    usermod -aG pxeboot dnsmasq && \
    /usr/sbin/setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=+ep' /usr/sbin/dnsmasq && \
    mkdir -p /var/lib/tftpboot /etc/dnsmasq.d /var/lib/dnsmasq /data/unpacked-iso && \
    wget https://boot.ipxe.org/ipxe.efi -O /var/lib/tftpboot/ipxe.efi && \
    chown -R dnsmasq:dnsmasq /var/lib/tftpboot /etc/dnsmasq.d /var/lib/dnsmasq && \
    chmod +x /entrypoint.sh && \
    chgrp -R pxeboot /data/unpacked-iso && \
    chmod -R g+w /data/unpacked-iso

HEALTHCHECK --interval=30s --timeout=5s CMD pgrep dnsmasq || exit 1

USER dnsmasq

ENTRYPOINT ["/entrypoint.sh"]
CMD ["dnsmasq"]


