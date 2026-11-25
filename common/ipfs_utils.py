
"""
IPFS storage utilities for MedVault.

Uses the standard Kubo HTTP RPC API.
Only encrypted medical-record bytes should be uploaded.
"""

import json
import os
from urllib.parse import urlparse

import requests


class IPFSStorageError(Exception):
    """Raised when an IPFS storage operation fails."""


class IPFSClient:
    def __init__(self, api_url=None, timeout=60):
        self.api_url = (
            api_url or os.getenv(
                "IPFS_API_URL", "http://127.0.0.1:5001"
            )
        ).rstrip("/")

        self.timeout = timeout

        parsed = urlparse(self.api_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("Invalid IPFS API URL")

        self.session = requests.Session()

    def add_bytes(self, data: bytes) -> str:
        """Upload bytes to IPFS and return their CID."""

        if not isinstance(data, bytes):
            raise TypeError("IPFS data must be bytes")

        if not data:
            raise ValueError("Cannot upload empty data")

        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/add",
                params={
                    "pin": "true",
                    "cid-version": "1",
                    "wrap-with-directory": "false",
                },
                files={
                    "file": (
                        "encrypted_record.bin",
                        data,
                        "application/octet-stream",
                    )
                },
                timeout=self.timeout,
            )

            response.raise_for_status()

            # Kubo can return newline-delimited JSON.
            result = None

            for line in response.text.splitlines():
                if line.strip():
                    result = json.loads(line)

            if not result or not result.get("Hash"):
                raise IPFSStorageError(
                    "IPFS did not return a valid CID"
                )

            return result["Hash"]

        except requests.RequestException as exc:
            raise IPFSStorageError(
                f"IPFS upload failed: {exc}"
            ) from exc
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise IPFSStorageError(
                f"Invalid IPFS upload response: {exc}"
            ) from exc

    def get_bytes(self, cid: str) -> bytes:
        """Retrieve content from IPFS using its CID."""

        if not isinstance(cid, str) or not cid.strip():
            raise ValueError("A valid CID is required")

        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/cat",
                params={"arg": cid},
                timeout=self.timeout,
            )

            response.raise_for_status()
            return response.content

        except requests.RequestException as exc:
            raise IPFSStorageError(
                f"IPFS download failed: {exc}"
            ) from exc

    def pin(self, cid: str) -> None:
        """Pin content on this IPFS node."""

        self._pin_operation("add", cid)

    def unpin(self, cid: str) -> None:
        """Remove this node's pin for the supplied CID."""

        self._pin_operation("rm", cid)

    def _pin_operation(self, operation: str, cid: str) -> None:
        if not isinstance(cid, str) or not cid.strip():
            raise ValueError("A valid CID is required")

        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/pin/{operation}",
                params={"arg": cid},
                timeout=self.timeout,
            )
            response.raise_for_status()

        except requests.RequestException as exc:
            raise IPFSStorageError(
                f"IPFS pin operation failed: {exc}"
            ) from exc


# Convenient default client for application use.
ipfs_client = IPFSClient()


def add_bytes(data: bytes) -> str:
    return ipfs_client.add_bytes(data)


def get_bytes(cid: str) -> bytes:
    return ipfs_client.get_bytes(cid)


def pin(cid: str) -> None:
    ipfs_client.pin(cid)


def unpin(cid: str) -> None:
    ipfs_client.unpin(cid)
