import os
try:
    from twilio.rest import Client
except ImportError:
    Client = None

def send_sms_otp(phone: str, otp: str):
    """
    Sends an OTP via SMS using Twilio.
    If FLASK_ENV=development and Twilio is not configured, prints to console.
    Otherwise, raises a RuntimeError if not configured or if twilio package is missing.
    """
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
    from_number = os.environ.get("TWILIO_FROM_NUMBER")

    is_dev = (os.environ.get("FLASK_ENV") == "development")

    if not all([account_sid, auth_token, from_number]) or Client is None:
        if is_dev:
            print(f"[DEV SMS OTP] {phone} → {otp}")
            return
        else:
            missing = []
            if not account_sid: missing.append("TWILIO_ACCOUNT_SID")
            if not auth_token: missing.append("TWILIO_AUTH_TOKEN")
            if not from_number: missing.append("TWILIO_FROM_NUMBER")
            if Client is None: missing.append("twilio package")
            raise RuntimeError(f"SMS provider not configured. Missing: {', '.join(missing)}. Cannot send OTP.")

    try:
        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=f"Your MedVault verification code is: {otp}\n\nThis code expires in 5 minutes.",
            from_=from_number,
            to=phone
        )
    except Exception as e:
        print(f"[SMS OTP Error] Failed to send SMS to {phone}: {e}")
        raise RuntimeError("Failed to send OTP via SMS.") from e
