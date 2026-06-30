from sqlalchemy import select
from sqlalchemy.orm import selectinload

from bas_engine.database.connection import AsyncSessionLocal

from bas_engine.database.models import (
    SimulationDB,
    ModuleResultDB,
    FindingDB
)

from bas_engine.models.simulation import (
    SimulationResult,
    AttackModuleResult,
    Finding
)


class SimulationRepository:

    # ------------------------------------------------
    # CREATE SIMULATION
    # ------------------------------------------------

    async def create_simulation(
        self,
        simulation: SimulationResult
    ):

        async with AsyncSessionLocal() as session:

            db_sim = SimulationDB(
                id=simulation.id,
                name=simulation.name,
                target=simulation.target,
                status=simulation.status,
                modules=simulation.modules,
                metadata_json=simulation.metadata,
                created_by=simulation.created_by,
                created_at=simulation.created_at,
                updated_at=simulation.updated_at,
                started_at=simulation.started_at,
                finished_at=simulation.finished_at
            )

            session.add(db_sim)

            await session.commit()

            await session.refresh(db_sim)

            return db_sim

    # ------------------------------------------------
    # UPDATE SIMULATION
    # ------------------------------------------------

    async def update_simulation(
        self,
        simulation: SimulationResult
    ):

        async with AsyncSessionLocal() as session:

            result = await session.execute(
                select(SimulationDB).where(
                    SimulationDB.id == simulation.id
                )
            )

            db_sim = result.scalar_one_or_none()

            if not db_sim:
                return None

            db_sim.status = simulation.status
            db_sim.updated_at = simulation.updated_at
            db_sim.started_at = simulation.started_at
            db_sim.finished_at = simulation.finished_at
            db_sim.modules = simulation.modules
            # --------------------------------------------
            # DETECTION VALIDATION
            # --------------------------------------------

            validation = simulation.metadata.get(
                "detection_validation"
            )

            if validation:

                db_sim.detection_summary = validation

                # M7 fix: use .get() with safe defaults to prevent KeyError crashes
                soc_score_block = validation.get("soc_score", {})
                db_sim.soc_score = (
                    soc_score_block.get("soc_score")
                    if isinstance(soc_score_block, dict)
                    else None
                )

                db_sim.coverage_data = validation.get("coverage", {})

                db_sim.blindspot_data = validation.get("blindspots", [])

                db_sim.sigma_rules = validation.get("sigma_rules", [])
            await session.commit()

            return db_sim

    # ------------------------------------------------
    # SAVE MODULE RESULTS
    # ------------------------------------------------

    async def save_module_results(
        self,
        simulation_id: str,
        module_results: list[AttackModuleResult]
    ):

        async with AsyncSessionLocal() as session:

            for mod in module_results:

                db_mod = ModuleResultDB(
                    simulation_id=simulation_id,
                    module=mod.module,
                    status=mod.status,
                    error=mod.error,
                    stats=mod.stats,
                    started_at=mod.started_at,
                    finished_at=mod.finished_at,
                    duration_s=mod.duration_s
                )

                session.add(db_mod)

                await session.flush()

                for finding in mod.findings:

                    db_finding = FindingDB(
                        id=finding.id,
                        module_result_id=db_mod.id,
                        title=finding.title,
                        description=finding.description,
                        severity=str(finding.severity),
                        mitre_id=finding.mitre_id,
                        evidence=finding.evidence,
                        remediation=finding.remediation,
                        raw_data=finding.raw_data,
                        timestamp=finding.timestamp
                    )

                    session.add(db_finding)

            await session.commit()

    # ------------------------------------------------
    # GET SIMULATION
    # ------------------------------------------------

    async def get_simulation(
        self,
        sim_id: str
    ):

        async with AsyncSessionLocal() as session:

            result = await session.execute(

                select(SimulationDB)

                .options(
                    selectinload(
                        SimulationDB.module_results
                    ).selectinload(
                        ModuleResultDB.findings
                    )
                )

                .where(
                    SimulationDB.id == sim_id
                )
            )

            db_sim = result.scalar_one_or_none()

            if not db_sim:
                return None

            return self._to_pydantic(db_sim)

    # ------------------------------------------------
    # LIST ALL
    # ------------------------------------------------

    async def list_simulations(self, limit: int = 100):

        # M8 fix: clamp limit to prevent unbounded eager loads / OOM
        limit = min(max(limit, 1), 200)

        async with AsyncSessionLocal() as session:

            result = await session.execute(

                select(SimulationDB)

                .options(
                    selectinload(
                        SimulationDB.module_results
                    )
                )

                .order_by(SimulationDB.created_at.desc())

                .limit(limit)
            )

            simulations = result.scalars().all()

            return [
                self._to_pydantic(s)
                for s in simulations
            ]

    # ------------------------------------------------
    # CONVERTER
    # ------------------------------------------------

    def _to_pydantic(
        self,
        db_sim
    ):
        from sqlalchemy.orm.attributes import instance_state

        module_results = []

        for mod in db_sim.module_results:

            findings = []
            
            # Check if findings were eagerly loaded
            state = instance_state(mod)
            if "findings" not in state.unloaded:
                for f in mod.findings:
                    findings.append(
                        Finding(
                            id=f.id,
                            title=f.title,
                            description=f.description,
                            severity=f.severity,
                            mitre_id=f.mitre_id,
                            evidence=f.evidence,
                            remediation=f.remediation,
                            raw_data=f.raw_data,
                            timestamp=f.timestamp
                        )
                    )

            module_results.append(

                AttackModuleResult(
                    module=mod.module,
                    status=mod.status,
                    findings=findings,
                    error=mod.error,
                    stats=mod.stats,
                    started_at=mod.started_at,
                    finished_at=mod.finished_at,
                    duration_s=mod.duration_s
                )
            )

        metadata = db_sim.metadata_json or {}
        
        # Reconstruct detection_validation from distinct columns
        if getattr(db_sim, 'detection_summary', None) is not None:
            metadata["detection_validation"] = db_sim.detection_summary
        elif getattr(db_sim, 'soc_score', None) is not None or getattr(db_sim, 'blindspot_data', None) is not None:
            metadata["detection_validation"] = {
                "soc_score": {"soc_score": db_sim.soc_score} if db_sim.soc_score is not None else {},
                "blindspots": db_sim.blindspot_data or {},
                "sigma_rules": getattr(db_sim, 'sigma_rules', []) or []
            }

        return SimulationResult(
            id=db_sim.id,
            name=db_sim.name,
            target=db_sim.target,
            modules=db_sim.modules or [],
            status=db_sim.status,
            created_by=db_sim.created_by,
            module_results=module_results,
            metadata=metadata,
            created_at=db_sim.created_at,
            updated_at=db_sim.updated_at,
            started_at=db_sim.started_at,
            finished_at=db_sim.finished_at
        )