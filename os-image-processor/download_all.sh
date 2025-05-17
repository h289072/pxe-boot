#!/usr/bin/env sh

set -euo pipefail

while getopts "d:i:l:m:w:" opt; do
  case $opt in
    d) DEST_DIR="$OPTARG" ;;
    i) IMAGE_DIR="$OPTARG" ;;
    j) MAX_JOBS="$OPTARG" ;;
    l) LOG_FILE="$OPTARG" ;;
    w) WORK_DIR="$OPTARG" ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

# --- Require IMAGE_DIR as a positional argument ---
if [ $# -lt 1 ]; then
  echo "Usage: $0 [-d dest_dir] [-i image_dir] [-w work_dir] [-j max_jobs] [-l log_file] METADATA_FILE" >&2
  exit 1
fi

# defaults
METADATA_FILE="$1"
BASE_DIR=$(dirname "$METADATA_FILE")
IMAGE_DIR="${IMAGE_DIR:-$BASE_DIR/download/images}"
WORK_DIR="${WORK_DIR:-$BASE_DIR/download/work}"
DEST_DIR="${DEST_DIR:-$BASE_DIR/unpacked-iso}"
LOG_FILE="${LOG_FILE:-/dev/stdout}"
LOG_DIR=$(dirname "$LOG_FILE")
MAX_JOBS="${MAX_JOBS:-3}"        # Maximum number of parallel downloads

TMP_DIR=$(mktemp -d)
# Trap function to remove the temp dir and move the ISO file if the script fails

handle_exit() {
    rm -rf $TMP_DIR
}
trap handle_exit EXIT

# ===========
# Check tools
# ===========

for tool in jq curl bsdtar sha256sum sha512sum ssh-keygen gpg; do
  if ! command -v "$tool" &> /dev/null; then
    echo "Required tool '$tool' is not installed." >> "$LOG_FILE"
    exit 1
  fi
done

# Create necessary directories
echo mkdir -p "$IMAGE_DIR" "$WORK_DIR" "$DEST_DIR" "$LOG_DIR"
mkdir -p "$IMAGE_DIR" "$WORK_DIR" "$DEST_DIR" "$LOG_DIR"

download_with_resume() {
  local url="$1"
  local output="$2"

  echo "Downloading: $url -> $output"

  # Try resume download
  set +e
  curl -C - -R -L -o "$output" "$url"
  local exit_code=$?
  set -e
  echo "Exit code: $exit_code"

  case "$exit_code" in
    0)
      echo "Download complete."
      return 0
      ;;
    33)
      echo "Server does not support resume. Retrying without resume..."
      set +e
      curl -R -L -o "$output" "$url"
      local exit_code=$?
      set -e
      echo "Download complete. Exit code: $exit_code"
      return $exit_code
      ;;
    *)
      echo "Download failed with exit code $exit_code"
      return $exit_code
      ;;
  esac
}

verify_file() {
    local file="$1"
    local filename="$2"
    local sha256="$3"
    local sha512="$4"
    local gpg_sig="$5"
    local gpg_key="$6"
    local ssh_sig="$7"
    local ssh_key="$8"
    local ssh_id="$9"

    local success=true

    # SHA-256
    if [ -n "$sha256" ]; then
        echo "Verifying SHA-256 checksum for $filename"
        echo "$sha256  $file" | sha256sum -c - || success=false
    fi

    # SHA-512
    if [ -n "$sha512" ]; then
        echo "Verifying SHA-512 checksum for $filename"
        echo "$sha512  $file" | sha512sum -c - || success=false
    fi

    # GPG
    if [ -n "$gpg_sig" ] && [ -n "$gpg_key" ]; then
        echo "Verifying GPG signature for $filename"
        export GNUPGHOME="${TMP_DIR}/gpg"
        mkdir -p "$GNUPGHOME"
        chmod 700 "$GNUPGHOME"
        local sig_file="${TMP_DIR%/}/$filename.sig"
        echo "$gpg_sig" > "$sig_file"
        echo "$gpg_key" | gpg --import
        gpg --verify "$sig_file" "$file" || success=false
    fi

    # SSH
    if [ -n "$ssh_sig" ] && [ -n "$ssh_key" ]; then
        echo "Verifying SSH signature for $filename"
        local sig_file="${TMP_DIR%/}/$filename.sshsig"
        local pubkey_file="${TMP_DIR%/}/$filename.pub"
        echo "$ssh_sig" > "$sig_file"
        echo "$ssh_key" > "$pubkey_file"
        ssh-keygen -Y verify -f "$pubkey_file" -I "${ssh_id}" -n file -s "$sig_file" < "$file" || success=false
    fi

    if [ "$success" = true ]; then
        return 0
    else
        return 1
    fi
}


# Function to download and verify a single file

download_and_verify() {
    local id="$1"
    local url="$2"
    local sha256="$3"
    local sha512="$4"
    local gpg_sig="$5"
    local gpg_key="$6"
    local ssh_sig="$7"
    local ssh_key="$8"
    local ssh_id="$9"

    local filename="${id}.iso"
    local temp_path="${WORK_DIR%/}/${filename}"
    local final_path="${IMAGE_DIR%/}/${filename}"

    # Prüfe ggf. vorhandene Datei
    local skip_download=false
    if [ -f "$final_path" ]; then
        echo "Verifying existing file: $final_path"
        if verify_file "$final_path" "$filename" "$sha256" "$sha512" "$gpg_sig" "$gpg_key" "$ssh_sig" "$ssh_key" "$ssh_id"; then
            echo "Existing file passed verification: $final_path"
            skip_download=true
        else
            echo "Verification failed for existing file: $final_path. Re-downloading..."
            rm -f "$final_path"
        fi
    else
        echo "No existing file: $final_path"
    fi

    if [ "$skip_download" = false ]; then
        echo "Downloading: $filename"
        download_with_resume "$url" "$temp_path"
        if ! verify_file "$temp_path" "$filename" "$sha256" "$sha512" "$gpg_sig" "$gpg_key" "$ssh_sig" "$ssh_key" "$ssh_id"; then
            echo "Downloaded file failed verification: $temp_path"
            return 1
        fi
        mv "$temp_path" "$final_path"
    fi

    local dest_path="${DEST_DIR%/}/${id}"
    echo "Extracting ISO file to ${dest_path}"
    chmod -R u+w "${dest_path:?}" || true
    rm -rf "${dest_path:?}" || true
    mkdir -p "$dest_path"
    bsdtar -xf "$final_path" -C "$dest_path"
    echo "Extraction successful: $dest_path"
}

# Set defaults
running_jobs=0
pids=""

# Read the metadata file and extract image objects
images=$(jq -c '.images[]' "$METADATA_FILE")

# Process each image object
echo "$images" | while IFS= read -r image; do
    # Extract each field separately using jq
    id=$(echo "$image" | jq -r '.id')
    url=$(echo "$image" | jq -r '.source_url')
    sha256=$(echo "$image" | jq -r '.verifications.sha256 // ""')
    sha512=$(echo "$image" | jq -r '.verifications.sha512 // ""')
    gpg_sig=$(echo "$image" | jq -r '.verifications.gpg.signature // ""')
    gpg_key=$(echo "$image" | jq -r '.verifications.gpg.key // ""')
    ssh_sig=$(echo "$image" | jq -r '.verifications.ssh.signature // ""')
    ssh_key=$(echo "$image" | jq -r '.verifications.ssh.key // ""')
    ssh_id=$(echo "$image" | jq -r '.verifications.ssh.signer_identity // ""')

    # Run the download_and_verify function as a background process
    download_and_verify "$id" "$url" "$sha256" "$sha512" "$gpg_sig" "$gpg_key" "$ssh_sig" "$ssh_key" "$ssh_id" 2>&1 | sed "s/^/[$id] /" >> "$LOG_FILE" &

    # Track the background process PID
    pids="$pids $!"

    # Increment the running jobs counter
    running_jobs=$((running_jobs + 1))

    # Wait for *any* job to finish (emulated)
    while [ "$running_jobs" -ge "$MAX_JOBS" ]; do
        for pid in $pids; do
            # check if the process is not running and collect it, removing it from the list of running jobs
            if ! kill -0 "$pid" 2>/dev/null; then
                if ! wait "$pid"; then
                    echo "Background job $pid failed (continuing)" >> "$LOG_FILE"
                else
                    echo "Background job $pid finished (continuing)" >> "$LOG_FILE"
                fi
                pids=$(echo $pids | sed "s/\b$pid\b//")
                running_jobs=$((running_jobs - 1))
                break
            fi
        done
        sleep 1
    done
done

# Wait for all background jobs to finish
failures=0
for pid in $pids; do
  if ! wait "$pid"; then
    failures=$((failures + 1))
  fi
done

# Check if any jobs failed
if [ "$failures" -gt 0 ]; then
  echo "$failures job(s) failed. Check logs in $LOG_FILE." >> "$LOG_FILE"
  exit 1
else
  echo "All images processed successfully." >> "$LOG_FILE"
fi