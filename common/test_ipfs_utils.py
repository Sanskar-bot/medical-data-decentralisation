"""Unit tests for the Kubo RPC client's hash/CID validation and retries."""

import hashlib
import json

import pytest
import requests

from common.ipfs_utils import IPFSClient, IPFSIntegrityError


class Response:
    def __init__(self, *, content=b"", payload=None):
        self.content = content
        self.text = json.dumps(payload) + "\n" if payload is not None else ""
        self.status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return json.loads(self.text)


class MemoryKubo:
    def __init__(self):
        self.blocks = {}
        self.failures = 0

    @staticmethod
    def cid(data):
        return "bafy" + hashlib.sha256(data).hexdigest()

    def post(self, url, *, params=None, files=None, timeout=None):
        if self.failures:
            self.failures -= 1
            raise requests.ConnectionError("temporary unavailable")
        if url.endswith("/api/v0/add"):
            data = files["file"][1]
            cid = self.cid(data)
            if params.get("only-hash") != "true":
                self.blocks[cid] = data
            return Response(payload={"Hash": cid})
        if url.endswith("/api/v0/cat"):
            return Response(content=self.blocks[params["arg"]])
        if url.endswith("/api/v0/id"):
            return Response(payload={"ID": "private-node"})
        return Response(payload={})


def test_fetch_checks_sha256_and_cid_and_rejects_tampering():
    kubo = MemoryKubo()
    client = IPFSClient(api_url="http://127.0.0.1:5001", session=kubo,
                        retries=1, pin_targets=[])
    payload = b"already-encrypted-payload"
    stored = client.store_ciphertext(payload)
    assert client.get_verified_bytes(stored.cid, stored.sha256) == payload

    kubo.blocks[stored.cid] = b"modified bytes"
    with pytest.raises(IPFSIntegrityError):
        client.get_verified_bytes(stored.cid, stored.sha256)


def test_request_retries_temporary_transport_failure():
    kubo = MemoryKubo()
    kubo.failures = 2
    client = IPFSClient(api_url="http://127.0.0.1:5001", session=kubo,
                        retries=3, backoff=0, pin_targets=[])
    assert client.add_bytes(b"encrypted") == MemoryKubo.cid(b"encrypted")

