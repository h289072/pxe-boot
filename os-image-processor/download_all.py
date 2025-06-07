#!/usr/bin/env python

import json
import hashlib
import os
import pathlib
import subprocess
import shutil
import logging
import asyncio
import aiofiles
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Union
from pypdl import Pypdl

# --- Configuration ---
DEFAULT_CONCURRENT_DOWNLOADS = 3
DEFAULT_DOWNLOAD_SEGMENTS = 4
DEFAULT_DOWNLOAD_RETRIES = 3

# --- Logging ---
def setup_logging(log_file: Optional[Path] = None) -> logging.Logger:
    """
    Configures the root logger to log to stdout and optionally a file.

    Args:
        log_file: The file to log to. If None, only log to stdout.

    Returns:
        The configured logger.
    """
    handlers = [logging.StreamHandler()]  # immer stdout
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=handlers
    )
    return logging.getLogger("download")

# --- Hash verification ---
def verify_hash(file_path: str, expected_hash: str, algo: str) -> bool:
    """
    Verifies the hash of a file against an expected hash.

    Args:
        file_path (str): The path to the file to verify.
        expected_hash (str): The expected hash value.
        algo (str): The hashing algorithm to use (e.g., 'sha256').

    Returns:
        bool: True if the file's hash matches the expected hash, False otherwise.
    """
    h = hashlib.new(algo)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest().lower() == expected_hash.lower()

# --- GPG verification ---
def verify_gpg(
    file_path: Path, sig_data: str, key_data: str, logger: logging.Logger
) -> bool:
    """
    Verifies the GPG signature of a file against a given key.

    Args:
        file_path (Path): The path to the file to verify.
        sig_data (str): The GPG signature to verify.
        key_data (str): The GPG key to use for verification.

    Returns:
        bool: True if the file's signature verifies correctly, False otherwise.
    """
    with TemporaryDirectory() as gpg_home:
        gpg = shutil.which("gpg")
        if not gpg:
            raise RuntimeError("gpg not installed")

        key_path = Path(gpg_home) / "key.asc"
        sig_path = Path(gpg_home) / "file.sig"

        key_path.write_text(key_data)
        sig_path.write_text(sig_data)

        try:
            subprocess.run(
                [gpg, "--homedir", gpg_home, "--import", str(key_path)],
                check=True
            )
            subprocess.run(
                [gpg, "--homedir", gpg_home, "--verify", str(sig_path), str(file_path)],
                check=True
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"GPG verification error: {e.stderr.decode()}")
            return False
        return True

# --- SSH signature verification ---
def verify_ssh(
    file_path: Path, sig_data: str, pubkey_data: str, signer_id: str, logger: logging.Logger
) -> bool:
    """
    Verifies the SSH signature of a file against a given public key and signer identity.

    Args:
        file_path (Path): The path to the file to verify.
        sig_data (str): The SSH signature data to verify.
        pubkey_data (str): The public key data for verification.
        signer_id (str): The identity of the signer.

    Returns:
        bool: True if the file's SSH signature verifies correctly, False otherwise.
    """
    with TemporaryDirectory() as tmp:
        sig_path = Path(tmp) / "file.sshsig"
        key_path = Path(tmp) / "file.pub"

        sig_path.write_text(sig_data)
        key_path.write_text(pubkey_data)

        cmd = [
            "ssh-keygen", "-Y", "verify",
            "-f", str(key_path),
            "-I", signer_id,
            "-n", "file",
            "-s", str(sig_path)
        ]

        with open(file_path, "rb") as f:
            try:
                subprocess.run(cmd, input=f.read(), check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"GPG verification error: {e.stderr.decode()}")
                return False
            return True

# --- Verification logic ---
def is_verified(
    file_path: Path, verifications: Optional[Dict[str, Union[str, Dict[str, str]]]], logger: logging.Logger
) -> bool:
    """
    Verifies the integrity of a file by checking its hashes and/or signatures.

    Args:
        file_path (Path): The path to the file to verify.
        verifications (Optional[Dict[str, Union[str, Dict[str, str]]]]): The verification data to use.
            If None, no verification is performed.

    Returns:
        bool: True if the file is verified, False otherwise.
    """
    if not file_path.exists():
        return False
    if not verifications:
        return True  # nothing to verify, consider verified

    sha256 = verifications.get("sha256", "")
    sha512 = verifications.get("sha512", "")
    gpg = verifications.get("gpg", {})
    ssh = verifications.get("ssh", {})

    if sha256 and not verify_hash(file_path, sha256, "sha256"):
        return False
    if sha512 and not verify_hash(file_path, sha512, "sha512"):
        return False
    if gpg and gpg.get("signature") and gpg.get("key"):
        if not verify_gpg(file_path, gpg["signature"], gpg["key"], logger):
            return False
    if ssh and ssh.get("signature") and ssh.get("key") and ssh.get("signer_identity"):
        if not verify_ssh(file_path, ssh["signature"], ssh["key"], ssh["signer_identity"], logger):
            return False
    return True

# --- Extraction ---
def extract_iso(iso_path: Path, dest_dir: Path, logger: logging.Logger) -> None:
    """
    Extracts an ISO file to a given destination directory.

    Args:
        iso_path (Path): The path to the ISO file to extract.
        dest_dir (Path): The path to the directory where the ISO file should be extracted.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["bsdtar", "-xf", str(iso_path), "-C", str(dest_dir)], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"GPG verification error: {e.stderr.decode()}")

# --- Processing task ---
def process_image(
    img: Dict[str, Union[str, Dict[str, str]]],
    segments: int,
    retries: int,
    work_dir: Path,
    image_dir: Path,
    dest_dir: Path,
    logger: logging.Logger
) -> None:
    """
    Downloads an image, verifies it and extracts it to its destination directory.

    Args:
        img (Dict[str, Union[str, Dict[str, str]]]): The image metadata to process.
        segments (int): The number of segments to split the download into.
        retries (int): The number of times to retry the download.
        work_dir (Path): The directory where the ISO file should be saved during processing.
        image_dir (Path): The directory where the verified ISO file should be saved.
        dest_dir (Path): The directory where the extracted image should be saved.
        logger (logging.Logger): The logger to use for logging.

    Returns:
        None
    """

    img_id = img["id"]
    url = img["source_url"]
    work_path = work_dir / f"{img_id}.iso"
    final_path = image_dir / f"{img_id}.iso"
    out_dir = dest_dir / img_id

    if is_verified(final_path, img, logger=logger):
        logger.info(f"Already verified: {img_id} -> {final_path}")
        return

    logger.info(f"Downloading: {img_id} from {url}")

    try:
        downloader = Pypdl(logger=logger)
        downloader.start(
            url=url,
            file_path=str(work_path),
            overwrite=True,
            block=True,
            retries=retries,
            segments=segments,
            display=False)
    except Exception as e:
        logger.error(f"Download failed: {img_id}: {e}")
        return

    if not is_verified(work_path, img, logger=logger):
        logger.error(f"Verification failed: {img_id}")
        return

    final_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(work_path, final_path)
    logger.info(f"Moved to image_dir: {final_path}")

    try:
        extract_iso(final_path, out_dir, logger)
        logger.info(f"Extracted {img_id} to {out_dir}")
    except subprocess.CalledProcessError:
        logger.error(f"Extraction failed for {img_id}")

# --- Main logic ---
async def main_async(
    metadata_file: str,
    max_jobs: int,
    segments: int,
    retries: int,
    image_dir: Optional[str] = None,
    work_dir: Optional[str] = None,
    dest_dir: Optional[str] = None,
    log_file: Optional[str] = None,
) -> None:
    """
    Download and verify ISO images in parallel.

    Args:
        metadata_file (str): Path to metadata JSON file.
        max_jobs (int): Maximum number of concurrent downloads.
        segments (int): Number of segments to split the download into.
        retries (int): Number of times to retry a download.
        image_dir (str, optional): Directory to store the downloaded images. Defaults to None.
        work_dir (str, optional): Directory to store the temporary files. Defaults to None.
        dest_dir (str, optional): Directory to store the extracted ISO files. Defaults to None.
        log_file (str, optional): File to write the logs to. Defaults to None.
    """
    logger = setup_logging(log_file)

    async with aiofiles.open(metadata_file) as f:
        meta: Any = json.loads(await f.read())

    base_dir = pathlib.Path(metadata_file).parent
    image_dir = pathlib.Path(image_dir or base_dir / "download/images")
    work_dir = pathlib.Path(work_dir or base_dir / "download/work")
    dest_dir = pathlib.Path(dest_dir or base_dir / "unpacked-iso")

    image_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_dir.chmod(0o775)

    loop = asyncio.get_running_loop()

    with ThreadPoolExecutor(max_workers=max_jobs) as executor:
        tasks = [loop.run_in_executor(executor, process_image, img, segments, retries, work_dir, image_dir, dest_dir, logger)
                 for img in meta["images"]]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Download and verify ISO images")
    parser.add_argument("-m", "--metadata", type=Path, help="Path to metadata JSON file")
    parser.add_argument("-i", "--image-dir",type=Path, help="Directory to store the downloaded image files")
    parser.add_argument("-w", "--work-dir", type=Path, help="Directory to store the temporary/downloading files")
    parser.add_argument("-d", "--dest-dir", type=Path, help="Directory to store the extracted extracted ISO files")
    parser.add_argument("-l", "--log-file", type=Path, help="File to write the logs to. Use stdout if not specified")
    parser.add_argument("-j", "--jobs", type=int, default=DEFAULT_CONCURRENT_DOWNLOADS)
    parser.add_argument("-s", "--segments", type=int, default=DEFAULT_DOWNLOAD_SEGMENTS)
    parser.add_argument("-r", "--retries", type=int, default=DEFAULT_DOWNLOAD_RETRIES)

    args = parser.parse_args()

    metadata_file = args.metadata or os.environ.get("METADATA_FILE") or "/data/meta.json"
    dest_dir = args.dest_dir or os.environ.get("UNPACKED_ISO_DIR") or "/data/unpacked-iso"

    asyncio.run(main_async(
        metadata_file=metadata_file,
        image_dir=args.image_dir,
        work_dir=args.work_dir,
        dest_dir=dest_dir,
        max_jobs=args.jobs,
        segments=args.segments,
        retries=args.retries,
        log_file=args.log_file
    ))
