"""
common/secure_key_store.py
==========================
RSA private key storage using Windows DPAPI via ctypes.

Keys are encrypted with CryptProtectData (tied to current Windows user/machine)
and stored as .dpapi files in %LOCALAPPDATA%\\MedVault\\keys\\.

This avoids the 2560-byte size limit of Windows Credential Manager that causes
CredWrite error 1783 with large RSA keys.

On Linux/macOS, keys are encrypted with AES-256-GCM using a machine-derived key
(Argon2id from /etc/machine-id or platform.node()). This is software-only
protection — not hardware-backed like Windows DPAPI.
"""

import ctypes
import ctypes.wintypes
import logging
import os
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Storage location (outside project folder) ────────────────────────────────
_KEYS_DIR = Path(
    os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
) / "MedVault" / "keys"

import sys as _sys

# ── DPAPI via ctypes ─────────────────────────────────────────────────────────
_WINDOWS = _sys.platform == "win32"

if _WINDOWS:
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    # BOOL CryptProtectData(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, PVOID, DWORD, DATA_BLOB*)
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),  # pDataIn
        ctypes.c_wchar_p,            # szDataDescr
        ctypes.POINTER(_DATA_BLOB),  # pOptionalEntropy
        ctypes.c_void_p,             # pvReserved
        ctypes.c_void_p,             # pPromptStruct
        ctypes.wintypes.DWORD,       # dwFlags
        ctypes.POINTER(_DATA_BLOB),  # pDataOut
    ]
    _crypt32.CryptProtectData.restype = ctypes.wintypes.BOOL

    # BOOL CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, PVOID, DWORD, DATA_BLOB*)
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),  # pDataIn
        ctypes.POINTER(ctypes.c_wchar_p),  # ppszDataDescr
        ctypes.POINTER(_DATA_BLOB),  # pOptionalEntropy
        ctypes.c_void_p,             # pvReserved
        ctypes.c_void_p,             # pPromptStruct
        ctypes.wintypes.DWORD,       # dwFlags
        ctypes.POINTER(_DATA_BLOB),  # pDataOut
    ]
    _crypt32.CryptUnprotectData.restype = ctypes.wintypes.BOOL

    def _dpapi_encrypt(data: bytes) -> bytes:
        """Encrypt bytes using DPAPI (current-user scope)."""
        data_in = _DATA_BLOB(len(data), ctypes.create_string_buffer(data, len(data)))
        data_out = _DATA_BLOB()
        ok = _crypt32.CryptProtectData(
            ctypes.byref(data_in),
            "MedVault",          # description
            None, None, None, 0, ctypes.byref(data_out),
        )
        if not ok:
            raise OSError(f"CryptProtectData failed (error {ctypes.GetLastError()})")
        try:
            return ctypes.string_at(data_out.pbData, data_out.cbData)
        finally:
            _kernel32.LocalFree(data_out.pbData)

    def _dpapi_decrypt(blob: bytes) -> bytes:
        """Decrypt a DPAPI blob; returns plaintext bytes."""
        data_in = _DATA_BLOB(len(blob), ctypes.create_string_buffer(blob, len(blob)))
        data_out = _DATA_BLOB()
        desc = ctypes.c_wchar_p()
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(data_in), ctypes.byref(desc),
            None, None, None, 0, ctypes.byref(data_out),
        )
        if not ok:
            raise OSError(f"CryptUnprotectData failed (error {ctypes.GetLastError()})")
        try:
            return ctypes.string_at(data_out.pbData, data_out.cbData)
        finally:
            _kernel32.LocalFree(data_out.pbData)

else:
    # ── Linux/macOS fallback: AES-256-GCM with machine-derived key ──────────
    # WARNING: This is SOFTWARE-ONLY protection. Unlike Windows DPAPI, it is
    # NOT hardware-backed. The key is derived from a machine identifier and is
    # only as secure as the filesystem permissions on the .dpapi files.
    # On Linux, protect the keys directory with chmod 700 at minimum.
    logger.warning(
        "[SecureKeyStore] Windows DPAPI not available — "
        "keys will be encrypted with AES-256-GCM using a machine-derived Argon2id key "
        "(software-only, NOT hardware-backed like DPAPI). "
        "Ensure %s has restrictive permissions (chmod 700).",
        _KEYS_DIR,
    )

    def _get_machine_id_bytes() -> bytes:
        """Read a stable machine identifier for key derivation."""
        # Linux: /etc/machine-id (128-bit random UUID set at install time)
        machine_id_path = "/etc/machine-id"
        if os.path.exists(machine_id_path):
            try:
                mid = open(machine_id_path).read().strip()
                if mid:
                    return mid.encode()
            except OSError:
                pass
        # macOS / fallback: use hostname (less stable but available everywhere)
        return platform.node().encode() or b"medvault-fallback-machine-id"

    def _derive_machine_key(salt: bytes) -> bytes:
        """
        Derive a 32-byte AES key from the machine identifier using Argon2id.
        Argon2id is memory-hard, providing better brute-force resistance than PBKDF2.
        """
        from argon2.low_level import hash_secret_raw, Type
        machine_id_bytes = _get_machine_id_bytes()
        return hash_secret_raw(
            secret=machine_id_bytes,
            salt=salt,
            time_cost=3,
            memory_cost=65536,  # 64 MiB
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )

    def _dpapi_encrypt(data: bytes) -> bytes:  # type: ignore[misc]
        """
        Encrypt data with AES-256-GCM using a machine-derived Argon2id key.
        File format: salt(16 bytes) || nonce(12 bytes) || AES-GCM-ciphertext
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt  = os.urandom(16)
        nonce = os.urandom(12)
        key   = _derive_machine_key(salt)
        ct    = AESGCM(key).encrypt(nonce, data, None)
        return salt + nonce + ct

    def _dpapi_decrypt(blob: bytes) -> bytes:  # type: ignore[misc]
        """
        Decrypt a blob produced by _dpapi_encrypt (Linux/macOS path).
        Expects: salt(16) || nonce(12) || AES-GCM-ciphertext
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if len(blob) < 28:  # 16 + 12 minimum
            raise ValueError("Corrupt key blob: too short")
        salt  = blob[:16]
        nonce = blob[16:28]
        ct    = blob[28:]
        key   = _derive_machine_key(salt)
        return AESGCM(key).decrypt(nonce, ct, None)


def _safe_filename(credential_id: str) -> str:
    """Convert credential ID to a safe filename."""
    return (credential_id
            .replace(":", "_")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(" ", "_")) + ".dpapi"


# ── Public API ───────────────────────────────────────────────────────────────

class SecureKeyStore:
    """
    DPAPI-backed key storage (Windows) / AES-GCM machine-key storage (Linux/macOS).

    Usage:
        SecureKeyStore.store_private_key("patient__ABCD1234", pem_bytes)
        pem = SecureKeyStore.load_private_key("patient__ABCD1234")
        SecureKeyStore.delete_private_key("patient__ABCD1234")
    """

    @staticmethod
    def store_private_key(credential_id: str, pem_bytes: bytes) -> None:
        if not isinstance(pem_bytes, (bytes, bytearray)):
            raise TypeError("pem_bytes must be bytes")
        _KEYS_DIR.mkdir(parents=True, exist_ok=True)
        encrypted = _dpapi_encrypt(bytes(pem_bytes))
        path = _KEYS_DIR / _safe_filename(credential_id)
        path.write_bytes(encrypted)
        logger.info("[SecureKeyStore] key stored → %s", path)

    @staticmethod
    def load_private_key(credential_id: str) -> bytes:
        path = _KEYS_DIR / _safe_filename(credential_id)
        if not path.exists():
            raise KeyError(
                f"Key '{credential_id}' not found at {path}. "
                "The key may have been deleted or registered on another "
                "machine/user. Please re-register."
            )
        return _dpapi_decrypt(path.read_bytes())

    @staticmethod
    def exists(credential_id: str) -> bool:
        return (_KEYS_DIR / _safe_filename(credential_id)).exists()

    @staticmethod
    def delete_private_key(credential_id: str) -> None:
        path = _KEYS_DIR / _safe_filename(credential_id)
        try:
            path.unlink()
            logger.info("[SecureKeyStore] deleted → %s", path)
        except FileNotFoundError:
            pass
