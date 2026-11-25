"""In-memory content-addressed client used by isolated server unit tests."""

import hashlib
import hmac

from common.ipfs_utils import IPFSIntegrityError, StoredCiphertext


class FakeIPFSClient:
    def __init__(self, api_url="http://fake-kubo:5001", pin_targets=None):
        self.api_url = api_url
        self.pin_targets = list(pin_targets or [])
        self.timeout = 5
        self.retries = 1
        self.backoff = 0
        self.blocks = {}
        self.pins = set()

    @staticmethod
    def cid_for(data):
        return "bafyfake" + hashlib.sha256(data).hexdigest()

    def store_ciphertext(self, data):
        cid = self.cid_for(data)
        self.blocks[cid] = data
        self.pins.add(cid)
        status = {"primary": "pinned"}
        status.update({name: "pinned" for name, _url in self.pin_targets})
        return StoredCiphertext(cid, hashlib.sha256(data).hexdigest(), len(data), status)

    def add_bytes(self, data):
        stored = self.store_ciphertext(data)
        return stored.cid

    def get_bytes(self, cid):
        return self.blocks[cid]

    def get_verified_bytes(self, cid, expected_sha256):
        data = self.get_bytes(cid)
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha256):
            raise IPFSIntegrityError("Ciphertext SHA-256 verification failed")
        if not hmac.compare_digest(self.cid_for(data), cid):
            raise IPFSIntegrityError("Ciphertext CID verification failed")
        return data

    def unpin_all(self, cid):
        self.pins.discard(cid)
        return {"primary": "unpinned", **{name: "unpinned" for name, _ in self.pin_targets}}

    def unpin(self, cid):
        self.pins.discard(cid)

    def list_pins(self):
        return set(self.pins)

    def health_status(self):
        return {"primary": True, **{name: True for name, _ in self.pin_targets}}

    def health(self):
        return all(self.health_status().values())

    def tamper(self, cid, replacement):
        self.blocks[cid] = replacement
