"""
Data models — Pydantic v2 schemas for the BAS Engine API.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ── Enums ──────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class SimulationStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


# ── Finding ────────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    id:          str
    title:       str
    description: str
    severity:    Severity
    mitre_id:    Optional[str]  = None   # e.g. T1110, T1059
    evidence:    Optional[str]  = None
    remediation: Optional[str]  = None
    raw_data:    Optional[dict] = None
    timestamp:   datetime       = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


# ── Attack Module Result ────────────────────────────────────────────────────────

class AttackModuleResult(BaseModel):
    module:      str
    status:      str                    # "success" | "error" | "partial"
    findings:    List[Finding]          = []
    error:       Optional[str]          = None
    stats:       Dict[str, Any]         = {}
    started_at:  Optional[datetime]     = None
    finished_at: Optional[datetime]     = None
    duration_s:  Optional[float]        = None

    class Config:
        use_enum_values = True


# ── Simulation Request ─────────────────────────────────────────────────────────

class SimulationRequest(BaseModel):
    name:     str                    = Field(..., description="Human-readable simulation name")
    target:   str                    = Field(..., description="Target host/IP/URL")
    modules:  List[str]              = Field(..., description="List of attack module names")
    parallel: bool                   = Field(False, description="Run modules in parallel")
    autonomous: bool                 = Field(False, description="Enable AI-driven autonomous module chaining")
    detailed_enumeration: bool       = Field(False, description="Flag to enable deeper read-only enumeration")
    options:  Dict[str, Any]         = Field(default_factory=dict, description="Per-module options")
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v):
        if not v:
            raise ValueError("At least one attack module must be specified")
        from bas_engine.attack_modules.registry import MODULE_REGISTRY
        for m in v:
            if m not in MODULE_REGISTRY:
                raise ValueError(f"Invalid module: {m}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        if not v or not v.strip():
            raise ValueError("Target cannot be empty")
        
        target_str = v.strip()
        import urllib.parse
        import socket
        import ipaddress

        if "://" not in target_str:
            parse_target = "http://" + target_str
        else:
            parse_target = target_str
            
        parsed = urllib.parse.urlparse(parse_target)
        hostname = parsed.hostname or target_str.split(':')[0]
        
        try:
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                ip_str = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(ip_str)
            except Exception:
                # If resolution fails, we pass it and let the module fail later
                return target_str

        # Enforce comprehensive SSRF safety:
        # Block ALL loopback, private (RFC-1918), link-local, reserved, and multicast addresses.
        # Also block cloud metadata endpoints by name before DNS resolution.
        _BLOCKED_HOSTNAMES = {
            "localhost",
            "metadata.google.internal",
            "metadata.internal",
        }
        if hostname.lower() in _BLOCKED_HOSTNAMES:
            raise ValueError(f"Target hostname '{hostname}' is blocked by SSRF policy.")

        # Loopback and cloud metadata are ALWAYS blocked — even for lab targets
        if ip_obj.is_loopback or ip_obj.is_unspecified:
            raise ValueError(
                f"Target resolves to a prohibited loopback address ({ip_obj})."
            )
        if str(ip_obj) == "169.254.169.254":
            raise ValueError("AWS metadata endpoint is blocked unconditionally.")

        # Private/RFC-1918 ranges: blocked by default UNLESS the operator
        # explicitly adds the IP to the LAB_TARGETS allowlist in .env
        # e.g. LAB_TARGETS=192.168.56.102,10.0.0.5
        if ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            import os
            lab_targets_raw = os.getenv("LAB_TARGETS", "")
            approved_lab_ips = {t.strip() for t in lab_targets_raw.split(",") if t.strip()}
            if str(ip_obj) not in approved_lab_ips:
                raise ValueError(
                    f"Target {ip_obj} is a private/reserved IP. "
                    "To scan a controlled lab VM, add it to LAB_TARGETS in your .env file. "
                    "Example: LAB_TARGETS=192.168.56.102"
                )

        return target_str





# ── Simulation Result ──────────────────────────────────────────────────────────

class SimulationResult(BaseModel):
    id:             str
    name:           str
    target:         str
    modules:        List[str]
    status:         str
    created_by:     Optional[str]              = None
    module_results: List[AttackModuleResult]   = []
    error:          Optional[str]              = None
    metadata:       Dict[str, Any]             = {}
    created_at:     datetime
    updated_at:     datetime
    started_at:     Optional[datetime]         = None
    finished_at:    Optional[datetime]         = None

    @property
    def duration_s(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.module_results)

    @property
    def critical_findings(self) -> int:
        return sum(
            1 for r in self.module_results
            for f in r.findings
            if f.severity in (Severity.CRITICAL, "critical")
        )

    class Config:
        use_enum_values = True


# ── Summary ────────────────────────────────────────────────────────────────────

class SimulationSummary(BaseModel):
    total:     int
    queued:    int
    running:   int
    completed: int
    failed:    int