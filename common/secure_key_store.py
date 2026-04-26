"""
common/secure_key_store.py
==========================
RSA private key storage using Windows DPAPI via ctypes.

Keys are encrypted with CryptProtectData (tied to current Windows user/machine)
and stored as .dpapi files in %LOCALAPPDATA%\\MedVault\\keys\\.

This avoids the 2560-byte size limit of Windows Credential Manager that causes
CredWrite error 1783 with large RSA keys.
"""

import ctypes
import ctypes.wintypes
import logging
import os
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
    # fix #11: cross-platform fallback — plaintext storage (no DPAPI available on Linux/macOS)
    logger.warning(
        "[SecureKeyStore] Windows DPAPI not available — "
        "keys will be stored in PLAINTEXT (development/Linux only)"
    )
    def _dpapi_encrypt(data: bytes) -> bytes:  # type: ignore[misc]
        return data  # no encryption

    def _dpapi_decrypt(blob: bytes) -> bytes:  # type: ignore[misc]
        return blob  # no decryption


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
    DPAPI-backed key storage.

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
