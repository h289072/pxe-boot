FROM alpine:latest

# Create default directory (can be overridden at runtime)
ENV UNPACKED_ISO_DIR=/data/unpacked-iso
VOLUME /data/unpacked-iso

COPY entrypoint.sh /entrypoint.sh

# Install lighttpd (klein, effizienter Webserver)
RUN apk add --no-cache lighttpd && \ 
    mkdir -p "$UNPACKED_ISO_DIR" && \
    chown -R lighttpd:lighttpd "$UNPACKED_ISO_DIR" /etc/lighttpd && \
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
