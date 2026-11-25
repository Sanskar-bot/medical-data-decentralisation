"""Private Kubo helpers for encrypted MedVault payloads.

Only callers that have already encrypted their data should use this module.
It never encrypts or decrypts payloads itself.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import requests


class IPFSStorageError(Exception):
    """Raised when a private IPFS storage operation fails."""


class IPFSIntegrityError(IPFSStorageError):
    """Raised when bytes do not match their stored digest or CID."""


@dataclass(frozen=True)
class StoredCiphertext:
    cid: str
    sha256: str
    size: int
    pin_status: dict[str, str]


def _is_private_api_url(value: str) -> bool:
    parsed = urlparse(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        return False
    host = parsed.hostname.lower()
    if host == "localhost" or "." not in host:
        return True  # Docker service name or other private DNS name.
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def configured_targets() -> list[tuple[str, str]]:
    """Return the primary and configured private Kubo API endpoints."""
    primary = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001").rstrip("/")
    if not _is_private_api_url(primary):
        raise ValueError("IPFS_API_URL must point to a private Kubo API")
    targets = [("primary", primary)]
    extras = os.getenv("IPFS_PIN_TARGETS", "")
    for index, entry in enumerate(filter(None, (x.strip() for x in extras.split(","))), 1):
        if "=" in entry:
            name, api_url = entry.split("=", 1)
            name = name.strip()
        else:
            name, api_url = f"replica_{index}", entry
        api_url = api_url.strip().rstrip("/")
        if not name or not _is_private_api_url(api_url):
            raise ValueError("IPFS_PIN_TARGETS must contain named private Kubo APIs")
        if any(existing_name == name or existing_url == api_url for existing_name, existing_url in targets):
            raise ValueError("IPFS pin target names and URLs must be unique")
        targets.append((name, api_url))
    return targets


class IPFSClient:
    """Small Kubo RPC client with bounded retries and content verification."""

    def __init__(self, api_url=None, timeout=None, retries=None, backoff=None,
                 session=None, pin_targets=None):
        self.api_url = (api_url or os.getenv("IPFS_API_URL", "http://127.0.0.1:5001")).rstrip("/")
        if not _is_private_api_url(self.api_url):
            raise ValueError("IPFS API URL must point to a private Kubo API")
        self.timeout = float(timeout or os.getenv("IPFS_TIMEOUT_SECONDS", "5"))
        self.retries = max(1, int(retries or os.getenv("IPFS_RETRIES", "3")))
        self.backoff = max(0.0, float(backoff if backoff is not None else os.getenv("IPFS_RETRY_BACKOFF_SECONDS", "0.15")))
        self.session = session or requests.Session()
        configured = pin_targets if pin_targets is not None else configured_targets()
        # Pin targets include primary by default. Do not duplicate the current endpoint.
        self.pin_targets = [(name, url.rstrip("/")) for name, url in configured
                            if url.rstrip("/") != self.api_url]

    def _post(self, path: str, *, params=None, files=None):
        last_error = None
        for attempt in range(self.retries):
            try:
                response = self.session.post(
                    f"{self.api_url}{path}", params=params, files=files,
                    timeout=self.timeout,
                )
                if response.status_code >= 500:
                    response.raise_for_status()
                response.raise_for_status()
                return response
            except requests.RequestException as exc:
                last_error = exc
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status is not None and status < 500:
                    break
                if attempt + 1 < self.retries:
                    time.sleep(self.backoff * (2 ** attempt))
        raise IPFSStorageError(f"Kubo request failed: {last_error}") from last_error

    @staticmethod
    def _parse_cid(response) -> str:
        result = None
        try:
            for line in response.text.splitlines():
                if line.strip():
                    result = json.loads(line)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise IPFSStorageError("Kubo returned invalid add response") from exc
        cid = result.get("Hash") if isinstance(result, dict) else None
        if not isinstance(cid, str) or not cid:
            raise IPFSStorageError("Kubo did not return a valid CID")
        return cid

    def _add(self, data: bytes, *, only_hash=False) -> str:
        response = self._post(
            "/api/v0/add",
            params={
                "pin": "false" if only_hash else "true",
                "only-hash": "true" if only_hash else "false",
                "cid-version": "1",
                "raw-leaves": "true",
                "wrap-with-directory": "false",
            },
            files={"file": ("payload.bin", data, "application/octet-stream")},
        )
        return self._parse_cid(response)

    def add_bytes(self, data: bytes) -> str:
        """Add already-encrypted bytes and pin them on the primary Kubo node."""
        if not isinstance(data, bytes):
            raise TypeError("IPFS data must be bytes")
        if not data:
            raise ValueError("Cannot upload empty data")
        try:
            return self._add(data)
        except IPFSStorageError:
            raise
        except (TypeError, ValueError) as exc:
            raise IPFSStorageError("Invalid IPFS upload response") from exc

    def store_ciphertext(self, data: bytes) -> StoredCiphertext:
        """Store bytes on the primary and attempt each configured replica."""
        cid = self.add_bytes(data)
        status = {"primary": "pinned"}
        for name, api_url in self.pin_targets:
            target = IPFSClient(
                api_url=api_url, timeout=self.timeout, retries=self.retries,
                backoff=self.backoff, session=self.session, pin_targets=[],
            )
            try:
                replica_cid = target.add_bytes(data)
                if replica_cid != cid:
                    raise IPFSIntegrityError("pin target calculated a different CID")
                status[name] = "pinned"
            except IPFSStorageError:
                status[name] = "pending"
        return StoredCiphertext(cid, hashlib.sha256(data).hexdigest(), len(data), status)

    def get_bytes(self, cid: str) -> bytes:
        """Retrieve bytes from this node. Callers should verify before use."""
        if not isinstance(cid, str) or not cid.strip():
            raise ValueError("A valid CID is required")
        response = self._post("/api/v0/cat", params={"arg": cid})
        return response.content

    def calculate_cid(self, data: bytes) -> str:
        """Ask Kubo to calculate the CID without pinning or storing content."""
        if not isinstance(data, bytes) or not data:
            raise ValueError("Non-empty bytes are required")
        return self._add(data, only_hash=True)

    def verify_bytes(self, cid: str, expected_sha256: str, data: bytes) -> None:
        digest = hashlib.sha256(data).hexdigest()
        if not isinstance(expected_sha256, str) or not hmac.compare_digest(digest, expected_sha256.lower()):
            raise IPFSIntegrityError("Ciphertext SHA-256 verification failed")
        actual_cid = self.calculate_cid(data)
        if not hmac.compare_digest(actual_cid, cid):
            raise IPFSIntegrityError("Ciphertext CID verification failed")

    def get_verified_bytes(self, cid: str, expected_sha256: str) -> bytes:
        """Fetch from any configured target and fail closed unless hash and CID match."""
        errors = []
        candidates = [("primary", self.api_url), *self.pin_targets]
        for _name, api_url in candidates:
            target = self if api_url == self.api_url else IPFSClient(
                api_url=api_url, timeout=self.timeout, retries=self.retries,
                backoff=self.backoff, session=self.session, pin_targets=[],
            )
            try:
                data = target.get_bytes(cid)
                target.verify_bytes(cid, expected_sha256, data)
                return data
            except IPFSStorageError as exc:
                errors.append(exc)
        raise IPFSIntegrityError("Ciphertext could not be fetched and verified") from (errors[-1] if errors else None)

    def ensure_pinned(self, cid: str, expected_sha256: str, target_url: str) -> None:
        data = self.get_verified_bytes(cid, expected_sha256)
        target = IPFSClient(
            api_url=target_url, timeout=self.timeout, retries=self.retries,
            backoff=self.backoff, session=self.session, pin_targets=[],
        )
        result_cid = target.add_bytes(data)
        if not hmac.compare_digest(result_cid, cid):
            raise IPFSIntegrityError("Pin target returned a different CID")

    def list_pins(self) -> set[str]:
        response = self._post("/api/v0/pin/ls", params={"type": "recursive"})
        try:
            keys = response.json().get("Keys", {})
            return set(keys)
        except (ValueError, AttributeError, TypeError) as exc:
            raise IPFSStorageError("Kubo returned invalid pin listing") from exc

    def unpin(self, cid: str) -> None:
        if not isinstance(cid, str) or not cid.strip():
            raise ValueError("A valid CID is required")
        self._post("/api/v0/pin/rm", params={"arg": cid})

    def unpin_all(self, cid: str) -> dict[str, str]:
        status = {}
        for name, api_url in [("primary", self.api_url), *self.pin_targets]:
            target = self if api_url == self.api_url else IPFSClient(
                api_url=api_url, timeout=self.timeout, retries=self.retries,
                backoff=self.backoff, session=self.session, pin_targets=[],
            )
            try:
                target.unpin(cid)
                status[name] = "unpinned"
            except IPFSStorageError:
                status[name] = "pending"
        return status

    def repo_gc(self) -> None:
        self._post("/api/v0/repo/gc")

    def health_status(self) -> dict[str, bool]:
        status = {}
        for name, api_url in [("primary", self.api_url), *self.pin_targets]:
            target = self if api_url == self.api_url else IPFSClient(
                api_url=api_url, timeout=self.timeout, retries=1,
                backoff=0, session=self.session, pin_targets=[],
            )
            try:
                target._post("/api/v0/id")
                status[name] = True
            except IPFSStorageError:
                status[name] = False
        return status

    def health(self) -> bool:
        return all(self.health_status().values())


ipfs_client = IPFSClient()


def add_bytes(data: bytes) -> str:
    return ipfs_client.add_bytes(data)


def get_bytes(cid: str) -> bytes:
    return ipfs_client.get_bytes(cid)


def pin(cid: str) -> None:
    # Legacy compatibility helper; with offline/private nodes pin only locally.
    ipfs_client._post("/api/v0/pin/add", params={"arg": cid})


def unpin(cid: str) -> None:
    ipfs_client.unpin(cid)
