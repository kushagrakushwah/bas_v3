import asyncio
import uuid
import logging
import importlib
from datetime import datetime
from typing import Dict, Optional, List
from enum import Enum

from bas_engine.repositories.simulation_repo import (
    SimulationRepository
)
from bas_engine.core.event_bus import EventBus
from bas_engine.models.simulation import (
    SimulationRequest,
    SimulationResult,
    SimulationStatus,
    AttackModuleResult,
    SimulationSummary
)
from bas_engine.detection.validation_engine import (
    DetectionValidationEngine
)

logger = logging.getLogger("secureforge.orchestrator")


class SimulationState(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


# ─── Module variant mapping ────────────────────────────────────────────────
# Maps module_name -> (safe_module_path, safe_class_name, red_module_path, red_class_name)
# or a dict with boolean keys.
# This tells the orchestrator which file/class to load for safe vs. aggressive mode.
MODULE_VARIANT_MAP = {
    "privilege_escalation": {
        False: ("bas_engine.attack_modules.privilege_escalation_safe", "PrivEscModule"),
        True:  ("bas_engine.attack_modules.privilege_escalation_red", "PrivEscModule"),
    },
    "impact_sim": {
        False: ("bas_engine.attack_modules.impact_sim_safe", "ImpactSimModule"),
        True:  ("bas_engine.attack_modules.impact_sim_red", "ImpactSimModule"),
    },
    # Add other modules here if they have _safe/_red variants.
    # If a module is not listed, we will fall back to the original registry.
}


class AttackOrchestrator:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.repo = SimulationRepository()
        self._store: Dict[str, SimulationResult] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(5)
        self.validation_engine = DetectionValidationEngine()
        logger.info("AttackOrchestrator initialized")

    async def launch(self, request: SimulationRequest) -> SimulationResult:
        sim_id = str(uuid.uuid4())
        now = datetime.utcnow()

        result = SimulationResult(
            id=sim_id,
            name=request.name,
            target=request.target,
            modules=request.modules,
            status=SimulationState.QUEUED,
            created_at=now,
            updated_at=now,
            module_results=[],
            metadata=request.metadata or {}
        )

        self._store[sim_id] = result
        await self.repo.create_simulation(result)

        task = asyncio.create_task(self._run_simulation(sim_id, request))
        self._tasks[sim_id] = task
        task.add_done_callback(lambda t: self._tasks.pop(sim_id, None))

        await self.event_bus.publish(
            "simulation.queued",
            {
                "id": sim_id,
                "name": request.name
            }
        )

        return result

    def get(self, sim_id: str) -> Optional[SimulationResult]:
        return self._store.get(sim_id)

    def list_all(self) -> List[SimulationResult]:
        return list(self._store.values())

    def summary(self) -> SimulationSummary:
        results = list(self._store.values())
        return SimulationSummary(
            total=len(results),
            queued=sum(1 for r in results if r.status == SimulationState.QUEUED),
            running=sum(1 for r in results if r.status == SimulationState.RUNNING),
            completed=sum(1 for r in results if r.status == SimulationState.COMPLETED),
            failed=sum(1 for r in results if r.status == SimulationState.FAILED),
        )

    async def _run_simulation(
        self,
        sim_id: str,
        request: SimulationRequest
    ):
        async with self._semaphore:
            result = self._store[sim_id]

            result.status = SimulationState.RUNNING
            result.started_at = datetime.utcnow()
            await self.repo.update_simulation(result)

            await self.event_bus.publish(
                "simulation.started",
                {
                    "id": sim_id,
                    "target": request.target
                }
            )

            try:
                # Pass the detailed_enumeration flag to each module runner
                module_tasks = [
                    self._run_module(
                        sim_id,
                        request.target,
                        m,
                        request.options,
                        request.detailed_enumeration  # <-- NEW
                    )
                    for m in request.modules
                ]

                # ----------------------------------------
                # PARALLEL / SEQUENTIAL EXECUTION
                # ----------------------------------------
                if request.parallel:
                    module_results = await asyncio.gather(
                        *module_tasks,
                        return_exceptions=True
                    )
                else:
                    module_results = []
                    for t in module_tasks:
                        module_results.append(await t)

                # ----------------------------------------
                # STORE MODULE RESULTS
                # ----------------------------------------
                result.module_results = []

                for r in module_results:
                    if isinstance(r, Exception):
                        logger.error(f"Module execution error: {r}")
                        continue

                    result.module_results.append(r)
                    print("\n=== MODULE RESULT ===")
                    print(r)
                    print("Findings:", len(r.findings))

                # ----------------------------------------
                # COLLECT FINDINGS
                # ----------------------------------------
                all_findings = []

                for mod in result.module_results:
                    print(f"\n=== MODULE {mod.module} ===")
                    print(f"Findings count: {len(mod.findings)}")

                    for finding in mod.findings:
                        print("Finding:", finding)

                        if hasattr(finding, "model_dump"):
                            f = finding.model_dump()
                        else:
                            f = finding.dict()

                        print("Serialized:", f)

                        all_findings.append({
                            "mitre_id": f.get("mitre_id"),
                            "severity": str(f.get("severity")),
                            "title": f.get("title")
                        })

                # ----------------------------------------
                # RUN DETECTION VALIDATION
                # ----------------------------------------
                print("\n=== FINDINGS SENT TO VALIDATION ===")
                print(all_findings)

                validation = self.validation_engine.validate(all_findings)

                print("\n=== VALIDATION RESULT ===")
                print(validation)

                # ----------------------------------------
                # STORE VALIDATION
                # ----------------------------------------
                result.metadata["detection_validation"] = validation

                # ----------------------------------------
                # COMPLETE
                # ----------------------------------------
                result.status = SimulationState.COMPLETED
                result.finished_at = datetime.utcnow()

                # ----------------------------------------
                # SAVE TO DATABASE
                # ----------------------------------------
                await self.repo.save_module_results(
                    sim_id,
                    result.module_results
                )
                await self.repo.update_simulation(result)

                await self.event_bus.publish(
                    "simulation.completed",
                    {
                        "id": sim_id
                    }
                )

            except Exception as exc:
                result.status = SimulationState.FAILED
                result.error = str(exc)
                result.finished_at = datetime.utcnow()

                await self.repo.update_simulation(result)

                await self.event_bus.publish(
                    "simulation.failed",
                    {
                        "id": sim_id,
                        "error": str(exc)
                    }
                )

    async def _run_module(
        self,
        sim_id: str,
        target: str,
        module_name: str,
        options: dict,
        detailed_enumeration: bool  # <-- NEW parameter
    ) -> AttackModuleResult:
        """
        Runs a single attack module.
        - If the module has a _safe / _red variant defined in MODULE_VARIANT_MAP,
          it imports the appropriate one based on detailed_enumeration.
        - Otherwise, it falls back to the original MODULE_REGISTRY.
        """
        # 1. Try to load a variant from the map
        variant_entry = MODULE_VARIANT_MAP.get(module_name)
        if variant_entry:
            module_path, class_name = variant_entry[detailed_enumeration]
            try:
                mod = importlib.import_module(module_path)
                module_cls = getattr(mod, class_name)
                logger.info(
                    f"Loading module {module_name} variant: "
                    f"{module_path}.{class_name} "
                    f"(detailed_enumeration={detailed_enumeration})"
                )
            except (ImportError, AttributeError) as e:
                logger.error(
                    f"Failed to import variant for {module_name}: {e}. "
                    "Falling back to registry."
                )
                module_cls = None
        else:
            # Fallback to the original registry (for modules without variants)
            from bas_engine.attack_modules.registry import MODULE_REGISTRY
            module_cls = MODULE_REGISTRY.get(module_name)

        if not module_cls:
            return AttackModuleResult(
                module=module_name,
                status="error",
                error=f"Module {module_name} not found"
            )

        # 2. Extract per-module options
        module_options = {}
        if isinstance(options, dict):
            module_options = options.get(module_name, {}) or {}

        # (Optional) still inject the flag in case the module wants it anyway
        module_options["detailed_enumeration"] = detailed_enumeration

        # 3. Instantiate and run
        module_instance = module_cls(
            target=target,
            options=module_options,
            sim_id=sim_id,
            event_bus=self.event_bus
        )

        await self.event_bus.publish(
            "module.started",
            {
                "sim_id": sim_id,
                "module": module_name
            }
        )

        mod_result = await module_instance.run()

        await self.event_bus.publish(
            "module.completed",
            {
                "sim_id": sim_id,
                "module": module_name,
                "findings_count": len(mod_result.findings)
            }
        )

        # Broadcast individual findings
        for finding in mod_result.findings:
            finding_data = (
                finding.model_dump()
                if hasattr(finding, "model_dump")
                else finding.dict()
            )

            await self.event_bus.publish(
                "vulnerability.found",
                {
                    "sim_id": sim_id,
                    "target": target,
                    "module": module_name,
                    "finding_details": finding_data
                }
            )

        return mod_result