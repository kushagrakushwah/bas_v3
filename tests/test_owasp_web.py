import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from bas_engine.attack_modules.owasp_web import OWASPWebModule
from bas_engine.core.event_bus import EventBus

@pytest.fixture
def mock_event_bus():
    return EventBus()

@pytest.mark.asyncio
async def test_owasp_ssrf_execution(mock_event_bus):
    module = OWASPWebModule(
        target="http://test.local",
        options={},
        event_bus=mock_event_bus
    )
    
    with patch("aiohttp.ClientSession") as mock_session_class:
        mock_session = AsyncMock()
        mock_session_class.return_value.__aenter__.return_value = mock_session
        
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_session.get.return_value.__aenter__.return_value = mock_resp
        
        # Test just the execution without hanging
        findings = await module.execute()
        assert isinstance(findings, list)
