# --- Build Stage: compile Python script into binary ---
FROM alpine:latest AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    python3-dev \
    build-base \
    libffi-dev \
    musl-dev \
    openssl-dev

# Create nonroot user (same UID as in Wolfi)
RUN adduser -D -u 65532 nonroot
USER nonroot
WORKDIR /home/nonroot

# Create and activate venv
RUN python3 -m venv /home/nonroot/venv
ENV PATH="/home/nonroot/venv/bin:$PATH"

# Install Python requirements and PyInstaller inside venv
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pyinstaller

# Copy your script into the container
COPY download_all.py .

# Build a static binary using PyInstaller
RUN pyinstaller \
    --onefile \
    --distpath dist \
    --name download_all \
    download_all.py

# --- Runtime Stage: only the compiled binary, not Python ---
FROM alpine:latest

ENV METADATA_FILE=/data/meta.json
ENV UNPACKED_ISO_DIR=/data/unpacked-iso

# Install only runtime libs needed for the binary
RUN apk add --no-cache \
    libffi \
    openssl \
    libarchive-tools \
    openssh \
    gnupg

# Create required mountpoints and user
VOLUME /data/unpacked-iso
VOLUME /data/download

RUN addgroup -g 10000 pxeboot && \
    adduser -D -u 65532 -G pxeboot nonroot && \
    mkdir -p /data/unpacked-iso /data/download && \
    chown -R nonroot:pxeboot /data && \
    chmod -R g+w /data

# Copy the compiled binary from the builder stage
COPY --from=builder /home/nonroot/dist/download_all /usr/local/bin/download_all

USER nonroot
WORKDIR /home/nonroot

# Run the binary with /data/meta.json as input
CMD [ "download_all" ]
