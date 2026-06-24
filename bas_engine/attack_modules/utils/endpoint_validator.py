import aiohttp


async def is_real_endpoint(
    session,
    target,
    path
):
    try:

        base_url = target.rstrip("/")

        probe_url = (
            base_url +
            path
        )

        async with session.get(
            base_url,
            ssl=True
        ) as base_resp:

            base_text = await base_resp.text()

        async with session.get(
            probe_url,
            ssl=True
        ) as probe_resp:

            if probe_resp.status != 200:
                return False

            probe_text = await probe_resp.text()

        # identical page
        if len(base_text) == len(probe_text):
            return False

        # Angular SPA fallback
        if (
            "<app-root>" in base_text.lower()
            and
            "<app-root>" in probe_text.lower()
        ):
            return False

        return True

    except Exception:
        return False
