FROM alpine:latest

# Create default directory (can be overridden at runtime)
ENV WWW_DIR=/data
ENV UNPACKED_ISO_DIR=/data/unpacked-iso
ENV IMAGE_DIR=/data/images
ENV SHARED_CONFIG_DIR=/data/config

VOLUME /data/unpacked-iso
VOLUME /data/images
VOLUME /data/config

COPY entrypoint.sh /entrypoint.sh

# Install lighttpd (klein, effizienter Webserver)
RUN apk add --no-cache \
        lighttpd \
        shadow && \
    addgroup -g 10000 pxeboot && \
    usermod -aG pxeboot lighttpd && \
    mkdir -p "$WWW_DIR" "$UNPACKED_ISO_DIR" "$IMAGE_DIR" "$SHARED_CONFIG_DIR" && \
    chown -R lighttpd:lighttpd /etc/lighttpd && \
    chown lighttpd:lighttpd "$WWW_DIR" && \
    chgrp -R pxeboot ${UNPACKED_ISO_DIR} ${IMAGE_DIR} ${SHARED_CONFIG_DIR} && \
    chmod +x /entrypoint.sh

# Switch to non-root user
USER lighttpd

# Expose port
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget --spider -q http://localhost/ || exit 1

# Start webserver
ENTRYPOINT ["/entrypoint.sh"]

# Redirect stdout to file descriptor 3, so logs can be written to stdout
# (because lightp closed stdout)
CMD ["sh", "-c", "exec 3>&1 && lighttpd -D -f /etc/lighttpd/lighttpd.conf"]
