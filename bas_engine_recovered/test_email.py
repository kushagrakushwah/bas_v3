import asyncio
import aiosmtplib
import os
import sys
import traceback
from email.mime.text import MIMEText

async def test():
    msg = MIMEText('test')
    msg['Subject'] = 'Test'
    msg['From'] = os.getenv('SMTP_USER')
    msg['To'] = os.getenv('SMTP_USER')
    print("Testing connection to", os.getenv('SMTP_SERVER'), os.getenv('SMTP_PORT'))
    print("User:", os.getenv('SMTP_USER'), "Pass length:", len(os.getenv('SMTP_PASS') or ''))
    try:
        await aiosmtplib.send(
            msg,
            hostname=os.getenv('SMTP_SERVER'),
            port=int(os.getenv('SMTP_PORT')),
            username=os.getenv('SMTP_USER'),
            password=os.getenv('SMTP_PASS'),
            use_tls=False,
            start_tls=True
        )
        print('SUCCESS')
    except Exception as e:
        print('ERROR:', e)
        traceback.print_exc()

asyncio.run(test())
