"""Async email sender."""

from email.message import EmailMessage

import aiosmtplib
from quart import current_app


async def send_email(subject, recipient, body, html=None, sender=None):
    app = current_app._get_current_object()
    sender = sender or app.config.get("SECURITY_EMAIL_SENDER")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = str(sender)
    message["To"] = recipient
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")

    await aiosmtplib.send(
        message,
        hostname=app.config.get("MAIL_SERVER", "localhost"),
        port=app.config.get("MAIL_PORT", 465),
        username=app.config.get("MAIL_USERNAME"),
        password=app.config.get("MAIL_PASSWORD"),
        use_tls=app.config.get("MAIL_USE_SSL", False),
        start_tls=app.config.get("MAIL_USE_TLS", False),
    )
