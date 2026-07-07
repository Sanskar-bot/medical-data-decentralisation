import os
import smtplib
from email.message import EmailMessage

def send_email_otp(email: str, otp: str):
    """
    Sends an OTP via email using SMTP.
    If FLASK_ENV=development and SMTP is not configured, prints to console.
    Otherwise, raises a RuntimeError if not configured.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT", "587")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_from = os.environ.get("SMTP_FROM_ADDRESS", "noreply@medvault.local")

    is_dev = (os.environ.get("FLASK_ENV") == "development")

    if not all([smtp_host, smtp_user, smtp_password]):
        if is_dev:
            print(f"[DEV EMAIL OTP] {email} → {otp}")
            return
        else:
            raise RuntimeError("Email provider (SMTP) not configured. Cannot send OTP.")

    try:
        msg = EmailMessage()
        msg.set_content(f"Your MedVault verification code is: {otp}\n\nThis code expires in 5 minutes.")
        msg["Subject"] = "MedVault Verification Code"
        msg["From"] = smtp_from
        msg["To"] = email

        with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
    except Exception as e:
        print(f"[Email OTP Error] Failed to send email to {email}: {e}")
        raise RuntimeError("Failed to send OTP via Email.") from e
