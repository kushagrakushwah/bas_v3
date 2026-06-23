import pytest
from bas_engine.models.simulation import SimulationRequest

def test_simulation_request_valid():
    req = SimulationRequest(name="Test", target="example.com", modules=["nmap_scan", "owasp_web"])
    assert req.target == "example.com"

def test_simulation_request_invalid_module():
    with pytest.raises(ValueError):
        SimulationRequest(name="Test", target="example.com", modules=["nonexistent_module"])

def test_simulation_request_ssrf_metadata():
    with pytest.raises(ValueError):
        SimulationRequest(name="Test", target="http://169.254.169.254/latest", modules=["nmap_scan"])

def test_simulation_request_ssrf_localhost():
    with pytest.raises(ValueError):
        SimulationRequest(name="Test", target="127.0.0.1", modules=["nmap_scan"])
