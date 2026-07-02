from sqlalchemy import select
from sqlalchemy.orm import selectinload

from bas_engine.database.connection import AsyncSessionLocal
from bas_engine.database.models import FindingDB
from bas_engine.models.simulation import Finding

class FindingsRepository:
    """
    Repository for querying findings across all simulations.
    This was previously an empty stub.
    """

    async def get_finding(self, finding_id: str) -> Finding | None:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(FindingDB).where(FindingDB.id == finding_id)
            )
            db_finding = result.scalar_one_or_none()
            if not db_finding:
                return None
            return Finding(
                id=db_finding.id,
                title=db_finding.title,
                description=db_finding.description,
                severity=db_finding.severity,
                mitre_id=db_finding.mitre_id,
                evidence=db_finding.evidence,
                remediation=db_finding.remediation,
                raw_data=db_finding.raw_data,
                timestamp=db_finding.timestamp
            )

    async def list_findings(self, limit: int = 100) -> list[Finding]:
        limit = min(max(limit, 1), 500)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(FindingDB)
                .order_by(FindingDB.timestamp.desc())
                .limit(limit)
            )
            findings = result.scalars().all()
            return [
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
                ) for f in findings
            ]
