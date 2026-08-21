from fastapi import APIRouter
from app.api.v1.endpoints import analyze, brands, nrd, export, telemetry

api_router = APIRouter()

api_router.include_router(telemetry.router, tags=["Telemetry & Health"])
api_router.include_router(analyze.router, tags=["Detection & Analysis"])
api_router.include_router(brands.router, tags=["Brand Catalog"])
api_router.include_router(nrd.router, tags=["Newly Registered Domains (NRD)"])
api_router.include_router(export.router, tags=["Threat Intelligence Export"])
