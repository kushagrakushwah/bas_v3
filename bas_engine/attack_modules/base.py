"""
BaseAttackModule — abstract base class every attack module must extend.
"""

from bas_engine.core.network.dns_resolver import (
    DNSResolver,
    ResolvedTarget,
)

import uuid
import logging
import ipaddress

from abc import ABC, abstractmethod

from datetime import datetime

from typing import List, Optional

from bas_engine.models.simulation import (

    AttackModuleResult,
    Finding,
    Severity
)

from bas_engine.core.events.event_stream import (
    EventStream
)

from bas_engine.core.events.ws_manager import (
    manager
)


class BaseAttackModule(ABC):
    """
    All attack modules inherit from this class.

    Subclass contract:
      1. Set MODULE_NAME
      2. Set DESCRIPTION
      3. Set MITRE_TACTIC
      4. Implement execute()

    run() handles:
    - timing
    - telemetry
    - websocket events
    - exception handling
    """

    MODULE_NAME: str = "base_module"

    DESCRIPTION: str = "Base attack module"

    MITRE_TACTIC: str = "Unknown"

    MITRE_IDS: List[str] = []


    # =====================================================
    # INIT
    # =====================================================

    def __init__(self, target: str, options: dict = None, sim_id: str = None, event_bus=None):

        self.target = target

        self.options = options or {}

        self.sim_id = sim_id or str(uuid.uuid4())
        self.event_bus = event_bus
        self._resolved_target: Optional[ResolvedTarget] = None

        self.logger = logging.getLogger(

            f"secureforge.module.{self.MODULE_NAME}"
        )


    # =====================================================
    # ABSTRACT EXECUTION
    # =====================================================

    @abstractmethod
    async def execute(self) -> List[Finding]:

        """
        Actual attack logic.
        Must return findings.
        """

        ...


    # =====================================================
    # TELEMETRY EMITTER
    # =====================================================

    async def emit_event(
        self,
        event_type: str,
        message: str,
        metadata: dict = None,
    ):
        # Print to terminal for visibility
        self.logger.info(f"[{event_type}] {message}")

        if self.event_bus:
            await self.event_bus.publish(
                "raw_event",
                {
                    "event_type": event_type,
                    "message": message,
                    "metadata": metadata or {},
                    "simulation_id": self.sim_id
                }
            )
        else:
            try:
                await manager.broadcast(
                    self.sim_id,
                    EventStream.build_event(
                        simulation_id=self.sim_id,
                        event_type=event_type,
                        message=message,
                        metadata=metadata or {},
                    )
                )
            except Exception as e:
                self.logger.warning(f"Event emit failed: {e}")

    async def resolve_target(self) -> ResolvedTarget:

        """
        Resolve and cache the current target once per module execution.

        Falls back to the original target when resolution fails so modules that
        accept CIDR ranges or non-DNS inputs can preserve their existing behavior.
        """

        if self._resolved_target is not None:
            return self._resolved_target

        raw_target = self.target.strip()

        try:
            network = ipaddress.ip_network(raw_target, strict=False)
        except ValueError:
            network = None

        if network is not None and ("/" in raw_target or raw_target == str(network)):
            resolved = ResolvedTarget(
                original=raw_target,
                hostname=None,
                ip=None,
                scheme=None,
                port=None,
                url=raw_target,
            )
            self._resolved_target = resolved
            return resolved

        try:
            resolved = await DNSResolver.resolve(raw_target)
        except Exception as exc:
            self.logger.debug(
                f"Target resolution failed for {raw_target}: {exc}"
            )

            resolved = ResolvedTarget(
                original=raw_target,
                hostname=None,
                ip=raw_target,
                scheme=None,
                port=None,
                url=raw_target,
            )

        self._resolved_target = resolved
        return resolved

    def build_target_url(
        self,
        resolved: Optional[ResolvedTarget] = None,
        default_scheme: str = "https",
    ) -> str:

        resolved = resolved or self._resolved_target
        if resolved is None:
            return f"{default_scheme}://{self.target.strip().lstrip('/')}"

        if resolved.url:
            return resolved.url.rstrip("/")

        if resolved.scheme and resolved.hostname:
            host = resolved.hostname
            if resolved.port:
                host = f"{host}:{resolved.port}"
            return f"{resolved.scheme}://{host}".rstrip("/")

        host = resolved.hostname or resolved.ip or resolved.original.strip()
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")
        return f"{default_scheme}://{host}".rstrip("/")


    # =====================================================
    # MAIN EXECUTION WRAPPER
    # =====================================================

    async def run(self) -> AttackModuleResult:

        started = datetime.utcnow()

        self.logger.info(

            f"[{self.MODULE_NAME}] "
            f"Starting against {self.target}"
        )

        # =================================================
        # START EVENT
        # =================================================

        await self.emit_event(

            "INFO",

            f"{self.MODULE_NAME} started",

            {

                "target": self.target,

                "module": self.MODULE_NAME,
            }
        )

        try:

            # =============================================
            # EXECUTE MODULE
            # =============================================

            findings = await self.execute()

            finished = datetime.utcnow()

            # =============================================
            # SUCCESS EVENT
            # =============================================

            await self.emit_event(

                "SUCCESS",

                f"{self.MODULE_NAME} completed",

                {

                    "findings":
                        len(findings),

                    "module":
                        self.MODULE_NAME,

                    "duration":
                        (
                            finished - started
                        ).total_seconds()
                }
            )

            # =============================================
            # FINDING EVENTS
            # =============================================

            for finding in findings:

                await self.emit_event(

                    "FINDING",

                    finding.title,

                    {

                        "severity":
                            str(
                                finding.severity
                            ),

                        "mitre_id":
                            finding.mitre_id,

                        "module":
                            self.MODULE_NAME,
                    }
                )

            # =============================================
            # RESULT
            # =============================================

            return AttackModuleResult(

                module=self.MODULE_NAME,

                status="success",

                findings=findings,

                started_at=started,

                finished_at=finished,

                duration_s=(
                    finished - started
                ).total_seconds(),

                stats={

                    "findings_count":
                        len(findings)
                },
            )

        # =================================================
        # EXCEPTION HANDLING
        # =================================================

        except Exception as exc:

            finished = datetime.utcnow()

            self.logger.error(

                f"[{self.MODULE_NAME}] "
                f"Error: {exc}",

                exc_info=True
            )

            # =============================================
            # ERROR EVENT
            # =============================================

            await self.emit_event(

                "ERROR",

                str(exc),

                {

                    "module":
                        self.MODULE_NAME
                }
            )

            return AttackModuleResult(

                module=self.MODULE_NAME,

                status="error",

                findings=[],

                error=str(exc),

                started_at=started,

                finished_at=finished,

                duration_s=(
                    finished - started
                ).total_seconds(),
            )


    # =====================================================
    # HELPER FINDING BUILDER
    # =====================================================

    def finding(

        self,

        title: str,

        description: str,

        severity: Severity,

        mitre_id: str = None,

        evidence: str = None,

        remediation: str = None,

        raw_data: dict = None,

        mode: Optional[str] = None,

        evidence_type: Optional[str] = None,
    ) -> Finding:

        enriched_raw_data = dict(raw_data or {})

        if mode:
            enriched_raw_data.setdefault("mode", mode)

        if evidence_type:
            enriched_raw_data.setdefault("evidence_type", evidence_type)

        return Finding(

            id=str(uuid.uuid4()),

            title=title,

            description=description,

            severity=severity,

            mitre_id=(
                mitre_id
                or (
                    self.MITRE_IDS[0]
                    if self.MITRE_IDS
                    else None
                )
            ),

            evidence=evidence,

            remediation=remediation,

            raw_data=enriched_raw_data or None,
        )
