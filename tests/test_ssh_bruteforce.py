import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from bas_engine.attack_modules.ssh_bruteforce import SSHBruteforceModule
from bas_engine.core.event_bus import EventBus

@pytest.fixture
def mock_event_bus():
    return EventBus()

@pytest.mark.asyncio
async def test_ssh_bruteforce_execution(mock_event_bus):
    module = SSHBruteforceModule(
        target="127.0.0.1",
        options={"ssh_bruteforce": {"auth_type": "ssh"}},
        event_bus=mock_event_bus
    )
    
    with patch("asyncssh.connect") as mock_connect:
        mock_conn = AsyncMock()
        mock_connect.return_value.__aenter__.return_value = mock_conn
        
        # We don't want it to actually run through the whole 50 wordlist payload for a basic test,
        # but just verifying it executes and returns a list.
        # Patching asyncio.sleep to speed up tests if it has delays
        with patch("asyncio.sleep", new_callable=AsyncMock):
            findings = await module.execute()
        
        assert isinstance(findings, list)
