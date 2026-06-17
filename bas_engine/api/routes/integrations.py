from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from bas_engine.database.connection import AsyncSessionLocal
from bas_engine.database.models import IntegrationDB

router = APIRouter()

class IntegrationCreate(BaseModel):
    name: str
    type: str
    target: str

@router.get("/")
async def get_integrations():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(IntegrationDB))
        return result.scalars().all()

@router.post("/")
async def create_integration(integration: IntegrationCreate):
    async with AsyncSessionLocal() as session:
        db_integration = IntegrationDB(
            name=integration.name,
            type=integration.type,
            target=integration.target
        )
        session.add(db_integration)
        await session.commit()
        await session.refresh(db_integration)
        return db_integration

@router.delete("/{integration_id}")
async def delete_integration(integration_id: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(IntegrationDB).where(IntegrationDB.id == integration_id))
        db_integration = result.scalar_one_or_none()
        if not db_integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        await session.delete(db_integration)
        await session.commit()
        return {"status": "success"}
