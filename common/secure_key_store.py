"""
common/secure_key_store.py
==========================
Production-level RSA private key storage using Windows Credential Manager
(DPAPI-backed) via the `keyring` library.

Security properties
-------------------
* Private key PEM bytes are base64-encoded and stored as a Windows Credential.
* DPAPI encrypts the value using the current Windows user's SID + machine key.
* Copying the project folder to another machine or user account yields an
  unusable credential — decryption will fail silently and the key cannot be
  extracted from the credential blob without the original Windows user session.
* The decrypted private key exists only in process memory during the request
  that needs it; it is never written to disk.
* No silent plaintext fallback exists. Missing credentials raise a
  clear KeyError so callers can surface a meaningful error to the user.

Why NOT the old approach
------------------------
plain `patient_private.pem`   → readable by any process with filesystem access.
`doctor_private_wrapped.b64`  → stores a KEK-wrapped key; still a file target
                                 for offline brute-force of the password.
"""

import base64
import logging
from typing import Optional

try:
    import keyring
    import keyring.errors
    _KEYRING_AVAILABLE = True
except ImportError:                          # pragma: no cover
    _KEYRING_AVAILABLE = False

logger = logging.getLogger(__name__)

# One service identifier shared across the whole app so all credentials are
# grouped together in Windows Credential Manager under "medvault".
_SERVICE = "medvault"


def _assert_keyring() -> None:
    """Raise RuntimeError if keyring is not importable."""
    if not _KEYRING_AVAILABLE:
        raise RuntimeError(
            "keyring library is not installed. "
            "Run:  pip install keyring"
        )


class SecureKeyStore:
    """
    Namespaced wrapper around Windows Credential Manager for RSA private keys.

    Usage
    -----
    # During registration (key in memory, never touched a file):
    SecureKeyStore.store_private_key("patient:f608wctx", priv_pem_bytes)

    # During any operation that needs decryption:
    priv_pem = SecureKeyStore.load_private_key("patient:f608wctx")
    priv     = rsa_load_private(priv_pem)
    # ... use priv, then let it go out of scope (GC clears memory)

    # On explicit deletion / account removal:
    SecureKeyStore.delete_private_key("patient:f608wctx")
    """

    @staticmethod
    def store_private_key(credential_id: str, pem_bytes: bytes) -> None:
        """
        Store RSA private key PEM bytes in Windows Credential Manager.

        Parameters
        ----------
        credential_id : str
            Unique identifier, e.g. "patient:<profile_code>" or
            "doctor:<doctor_code>".
        pem_bytes : bytes
            Raw PEM-encoded private key (e.g. from rsa_serialize_private()).

        Raises
        ------
        RuntimeError
            If keyring is not installed.
        keyring.errors.KeyringError
            If Windows Credential Manager is unavailable.
        """
        _assert_keyring()
        if not isinstance(pem_bytes, (bytes, bytearray)):
            raise TypeError("pem_bytes must be bytes")
        # base64-encode so the credential value is ASCII-safe
        encoded = base64.b64encode(pem_bytes).decode("ascii")
        keyring.set_password(_SERVICE, credential_id, encoded)
        logger.info("[SecureKeyStore] stored key for '%s'", credential_id)

    @staticmethod
    def load_private_key(credential_id: str) -> bytes:
        """
        Load RSA private key PEM bytes from Windows Credential Manager.

        Parameters
        ----------
        credential_id : str
            Same identifier used in store_private_key().

        Returns
        -------
        bytes
            Raw PEM bytes, ready to pass to rsa_load_private().

        Raises
        ------
        KeyError
            If no credential with this ID exists (e.g. re-registered elsewhere).
        RuntimeError
            If keyring is not installed.
        """
        _assert_keyring()
        encoded: Optional[str] = keyring.get_password(_SERVICE, credential_id)
        if encoded is None:
            raise KeyError(
                f"Private key '{credential_id}' not found in Windows Credential "
                "Manager. The key may have been deleted or this account was "
                "registered on a different machine/user. Please re-register."
            )
        return base64.b64decode(encoded)

    @staticmethod
    def exists(credential_id: str) -> bool:
        """Return True if a credential for this ID exists in the store."""
        _assert_keyring()
        return keyring.get_password(_SERVICE, credential_id) is not None

    @staticmethod
    def delete_private_key(credential_id: str) -> None:
        """
        Remove a credential from Windows Credential Manager.

        Safe to call even if the credential does not exist.

        Parameters
        ----------
        credential_id : str
            Same identifier used in store_private_key().
        """
        _assert_keyring()
        try:
            keyring.delete_password(_SERVICE, credential_id)
            logger.info("[SecureKeyStore] deleted key for '%s'", credential_id)
        except keyring.errors.PasswordDeleteError:
            pass   # already absent; treat as success
