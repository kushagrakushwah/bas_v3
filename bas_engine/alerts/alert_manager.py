import os
import json
import socket
import ipaddress
import logging
import aiohttp
import aiosmtplib

from email.mime.text import MIMEText
from sqlalchemy import select
from bas_engine.database.connection import AsyncSessionLocal
from bas_engine.database.models import IntegrationDB

logger = logging.getLogger("secureforge.alerts")

# ---------------------------------------------------------------------------
# Internal network ranges — used to block SSRF in outbound webhook calls.
# This is a RUNTIME guard that complements the Pydantic registration-time
# validator in integrations.py. An attacker who can modify the DB record
# directly must still pass this check before we send any bytes outbound.
# ---------------------------------------------------------------------------
_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud-metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
]


import asyncio

async def _is_safe_webhook_url(url: str) -> bool:
    """
    Return True only when the webhook URL resolves to a public, routable IP.
    Blocks RFC-1918, loopback, link-local (including AWS/GCP/Azure metadata),
    and non-HTTP(S) schemes to prevent SSRF and data exfiltration.
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.warning(f"Webhook blocked: non-HTTP scheme '{parsed.scheme}' in {url!r}")
            return False
        hostname = parsed.hostname or ""
        if not hostname:
            return False
        try:
            ip_str = await asyncio.to_thread(socket.gethostbyname, hostname)
            ip_obj = ipaddress.ip_address(ip_str)
        except socket.gaierror:
            # DNS failure — allow (will fail at connect time, not our SSRF concern)
            return True
        for net in _INTERNAL_NETS:
            try:
                if ip_obj in net:
                    logger.warning(
                        f"Webhook SSRF blocked: {url!r} resolves to internal IP {ip_obj}"
                    )
                    return False
            except TypeError:
                pass
        return True
    except Exception as exc:
        logger.error(f"Webhook safety check error: {exc}")
        return False


# ---------------------------------------------------
# SLACK / GENERIC WEBHOOK ALERT
# ---------------------------------------------------

async def send_slack_alert(message, webhook_url):
    if not webhook_url:
        return False

    # Runtime SSRF guard — second gate after the registration-time Pydantic check.
    if not await _is_safe_webhook_url(webhook_url):
        logger.error(
            f"send_slack_alert: outbound request to {webhook_url!r} blocked by SSRF policy"
        )
        return False

    payload = {"text": message}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                return resp.status == 200

    except Exception as exc:
        logger.warning(f"send_slack_alert failed: {exc}")
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
            start_tls=True,
        )

        return True

    except Exception as e:
        import traceback
        logger.error(f"SMTP EXCEPTION: {e}\n{traceback.format_exc()}")
        return False


# ---------------------------------------------------
# MAIN ALERT PIPELINE
# ---------------------------------------------------

async def process_alert(event):

    event_type = event.get("type", "")
    payload = event.get("payload", {})

    # Only alert on high-value events
    interesting = [
        "vulnerability.found",
        "simulation.failed",
        "module.completed",
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

    message = f"""SecureForge Alert

Event: {event_type}

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
                    integration.target,
                )