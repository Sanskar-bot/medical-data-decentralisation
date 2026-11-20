"""Demonstration only; this script is not production code."""

from datetime import datetime, timedelta, timezone
import uuid

from common.crypto_utils import generate_rsa_keypair
from common.share_scheme import ShareExpired, create_share, open_share


def main():
    patient_private, patient_public = generate_rsa_keypair(2048)
    doctor_private, doctor_public = generate_rsa_keypair(2048)
    patient_code = "DEMO-PATIENT"
    doctor_code = "DEMO-DOCTOR"
    share_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    selected_snapshot = b"Demonstration snapshot"

    share = create_share(
        selected_snapshot, patient_private, doctor_public, share_id,
        patient_code, doctor_code, expires_at,
    )
    opened = open_share(share, doctor_private, patient_public, doctor_code)
    print("Share created and opened successfully.")
    print(f"Snapshot matches: {opened == selected_snapshot}")

    simulated_now = datetime.fromisoformat(expires_at) + timedelta(seconds=1)
    try:
        open_share(share, doctor_private, patient_public, doctor_code, now=simulated_now)
    except ShareExpired:
        print("The client refused the share after simulated expiry.")


if __name__ == "__main__":
    main()
