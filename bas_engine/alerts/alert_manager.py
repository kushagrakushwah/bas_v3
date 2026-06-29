import os
import json
import aiohttp
import aiosmtplib

from email.mime.text import MIMEText
from sqlalchemy import select
from bas_engine.database.connection import AsyncSessionLocal
from bas_engine.database.models import IntegrationDB

# ---------------------------------------------------
# SLACK ALERT
# ---------------------------------------------------

async def send_slack_alert(message, webhook_url):

    if not webhook_url:
        return False

    payload = {
        "text": message
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=5
            ) as resp:
                return resp.status == 200

    except Exception:
        return False

# ---------------------------------------------------
# EMAIL ALERT
# ---------------------------------------------------

async def send_email_alert(subject, body, recipient):

    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")

    if not all([smtp_server, smtp_user, smtp_pass, recipient]):
        return False

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_user
        msg["To"] = recipient

        await aiosmtplib.send(
            msg,
            hostname=smtp_server,
            port=smtp_port,
            username=smtp_user,
            password=smtp_pass,
            use_tls=False,
            start_tls=True
        )

        return True

    except Exception as e:
        import traceback
        print(f"SMTP EXCEPTION: {e}", flush=True)
        traceback.print_exc()
        return False

# ---------------------------------------------------
# MAIN ALERT PIPELINE
# ---------------------------------------------------

async def process_alert(event):

    event_type = event.get(
        "type",
        ""
    )

    payload = event.get(
        "payload",
        {}
    )

    # Only alert on high-value events
    interesting = [

        "vulnerability.found",
        "simulation.failed",
        "module.completed"
    ]

    if event_type not in interesting:
        return

    import datetime

    class DateTimeEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return super().default(obj)

    try:
        payload_str = json.dumps(payload, indent=2, cls=DateTimeEncoder)
    except Exception:
        payload_str = str(payload)

    message = f"""
🚨 SecureForge Alert

Event:
{event_type}

Payload:
{payload_str}
"""

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IntegrationDB).where(IntegrationDB.status == "Active")
        )
        integrations = result.scalars().all()

        for integration in integrations:
            if integration.type == "Webhook":
                await send_slack_alert(message, integration.target)
            elif integration.type == "SMTP":
                await send_email_alert(
                    f"SecureForge Alert: {event_type}",
                    message,
                    integration.target
                )