# System Model, Threat Model and Security Goals

## System Model

We present MedVault, a research prototype of consent-based sharing for encrypted patient records. The system comprises a backend REST API server, a PostgreSQL database, server-side patient and doctor web portals, and an Nginx reverse proxy providing TLS termination, deployed as Docker containers on a single host.

The patient's registration record is encrypted (AES-256-GCM, key wrapped with RSA-4096 OAEP) [CITE]. Most clinical data added later (notes, prescriptions, vitals, lab results) is stored in plaintext. Encryption and key handling currently happen in the portal server.

$K_{\text{data}}$ is protected at rest by wrapping it with a KEK derived from the patient's password using PBKDF2-HMAC-SHA256 with 200,000 iterations [CITE]. Private keys are stored using platform credential protection: Windows DPAPI [CITE] or, on Linux, AES-256-GCM with an Argon2id-derived machine key [CITE].

## Threat Model

We consider the following actors and assumptions:

**A1.** The patient is honest and acts in their own interest. The patient's device (browser) is assumed to be uncompromised during active sessions.

**A2.** Doctors are semi-trusted: they are authenticated and authorized by the system, but may attempt to retain data beyond their authorized access window. A doctor who has legitimately decrypted $K_{\text{data}}$ cannot be prevented from retaining it.

**A3.** The network attacker is a Dolev-Yao adversary [CITE] who can intercept, replay, and modify network messages. This threat is mitigated by mandatory TLS 1.2+ with HSTS.

**A4.** The server infrastructure (backend, portals, database) is semi-trusted. In the current prototype, the portal servers generate cryptographic keys and perform encryption and decryption operations on behalf of the patient. A compromised server can therefore access plaintext data and private keys. This is a known limitation of the prototype; the planned design moves all cryptographic operations to an Android app on the patient's device, using Android Keystore for hardware-backed key protection where available. No mobile code exists in this repository yet (PLANNED, NOT IMPLEMENTED).

**Planned patient device (NOT IMPLEMENTED).** The patient client is planned as an Android app. No mobile code exists in this repository yet. The app is intended to hold the patient's records and private key on the device, using Android Keystore for key protection where available.

**Planned doctor verification (NOT IMPLEMENTED).** Doctor identity is planned to be verified by checking the doctor's licence number against a medical council registry. Currently an administrator creates doctor accounts manually. The schema has `doctor_license_number` and `doctor_verification_status` columns, but no verification logic is implemented.

Registry lookup availability, accuracy, and licence-number-to-person binding are unresolved. A licence number alone does not prove the person registering is that doctor.

**A5.** The database administrator can read all data stored in the database. In the current prototype, most clinical data (prescriptions, clinical notes, vitals, lab results, conditions, encounter summaries) is stored in plaintext. Only the patient's initial registration record is stored as an encrypted blob.

**A6.** A malicious insider (operator, hosting provider) has access to the host filesystem, container volumes, and the machine identifier used for key derivation, and can therefore recover private keys and plaintext data.

**A7.** For the per-share snapshot scheme, doctors are assumed to follow the protocol and not intentionally copy or leak a decrypted snapshot. Expiry cannot force deletion of information already seen by a doctor [CITE].

**A8.** The current prototype trusts its server-side key directory. No client independently authenticates the binding between patient or doctor identities and their public keys. A key substitution can make signature verification establish consistency with the substituted key rather than the named patient's identity [CITE].

The per-share snapshot scheme creates an immutable copy of only the patient-selected data, encrypts it under a fresh one-time AES key, wraps that key to one named doctor's public key, and signs the package. The share ID, patient, doctor, and expiry are authenticated with the ciphertext [CITE]. The patient's permanent data key is not shared. This provides best-effort expiry and accountability: a doctor can retain plaintext after a legitimate fetch, and database backups or WAL may retain encrypted copies. In the current deployment, server-side portals handle private keys and plaintext, so the server is not blind to plaintext; native client execution is future work [CITE].

The cryptographic binding does not by itself authenticate public keys. The backend supplies the patient's public key to the doctor, while the patient obtains the doctor's public key from the server directory. A malicious server could substitute either key; a valid signature would then authenticate only under the supplied key, not establish the named person's identity [CITE]. A phone-first design must address key discovery, rotation, and recovery using mechanisms such as out-of-band fingerprint comparison, key pinning, or certificates bound to registry-verified identities. Pinning alone leaves first contact exposed, and registry-based verification is not implemented [CITE].

## Security Goals

The system pursues the following security goals:

**G1. Confidentiality of the registration record.** The patient's initial registration data shall be readable only by the patient and doctors to whom the patient has granted consent, enforced by AES-256-GCM encryption in the current consent-based sharing prototype for encrypted patient records.

**G2. Consent-based access.** No doctor shall receive cryptographic access material without an explicit approval action by the patient.

**G3. Time-bounded access tokens.** Wrapped-key access has a 24-hour server-side expiry; JWT-based approvals (`access_db`) currently have no expiry. Once a doctor decrypts a key or record, access cannot be cryptographically revoked.

**G4. Transport confidentiality.** All client–server communication shall be protected by TLS 1.2 or higher.

**G5. Credential protection.** Passwords shall be stored as salted hashes. Private keys shall be protected at rest using platform-specific mechanisms (DPAPI or Argon2id-derived encryption).

**G6. Auditability.** All access events (data reads, consent grants, consent revocations) shall be recorded in an append-only audit log.

**G7. Per-share snapshot isolation and expiry.** Each new snapshot share shall use a fresh key wrapped only to its named doctor, with recipient and expiry authenticated by the patient's signature; the server shall stop serving it after expiry and clear live ciphertext and wrapped-key fields [CITE]. This goal does not promise deletion of plaintext already fetched by a doctor.

**G8. Authenticated key binding (future work).** A future client design shall authenticate the public keys used for patient signature verification and doctor key wrapping against their claimed identities. The current server-supplied key directory does not meet this goal [CITE].

## Non-Goals

The following are explicitly outside the scope of the current prototype:

- **Post-decryption revocation.** Once a doctor has decrypted $K_{\text{data}}$, the system cannot retroactively revoke access to data already obtained. This is a fundamental limitation shared by all key-sharing schemes [CITE].
- **Protection against a compromised server.** The prototype trusts the portal servers to handle cryptographic material honestly.
- **Metadata privacy.** The server observes which doctors request access to which patients and the timing of consent decisions.
- **Coercion resistance.** The system does not detect or resist scenarios in which a patient is compelled to grant access.
- **Regulatory compliance.** The prototype is not designed or validated for compliance with HIPAA [CITE], GDPR [CITE], or any other regulatory framework.

## Limitations

The current prototype has several limitations that should be addressed before any clinical deployment. First, cryptographic operations are performed by the server-side portal rather than on the patient's device, meaning the portal is a trusted intermediary with access to plaintext and private keys. Second, while the initial registration record is encrypted, most clinical data — prescriptions, notes, vitals, lab results, conditions, and encounters — is stored in plaintext. Third, the KEK for $K_{\text{data}}$ is derived from the login password using PBKDF2; the same password is transmitted to the backend during authentication, creating a single point of compromise. Fourth, the access-control check grants implicit permanent access if a doctor has previously written clinical data for the patient. Fifth, the access-approval endpoint is protected by a shared API key rather than patient-specific authentication. These limitations represent the gap between the prototype and its planned phone-first design.
