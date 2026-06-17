"""
FastAPI Router for CyCraft AIR™ (Automated Incident Response)
"""

from fastapi import APIRouter
from cycraft.services.air_runner import air_runner

router = APIRouter(prefix="/air", tags=["Automated Incident Response"])

@router.post("/run-pipeline/{scenario_idx}")
async def execute_air_pipeline(scenario_idx: int):
    """
    Execute an autonomous AIR incident resolution pipeline for a specific attack scenario
    """
    result = await air_runner.run_pipeline_scenario(scenario_idx=scenario_idx)
    return result
