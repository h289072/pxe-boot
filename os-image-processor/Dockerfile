FROM cgr.dev/chainguard/wolfi-base

# Install necessary packages
RUN apk update && apk add --no-cache \
    jq \
    curl \
    libarchive-tools \
    coreutils \
    openssh \
    gpg \
    gnupg-agent

VOLUME /data/unpacked-iso
VOLUME /data/download

# Copy scripts
COPY download_all.sh /usr/local/bin/download_all.sh
RUN chmod +x /usr/local/bin/download_all.sh && \
    mkdir -p /data/unpacked-iso /data/download && \
    chown -R nonroot:nonroot /data

# Switch to nonroot user
USER nonroot

# Set the entrypoint
CMD ["/usr/local/bin/download_all.sh", "-d", "/data/unpacked-iso", "/data/meta.json"]

