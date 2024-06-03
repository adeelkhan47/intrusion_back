from fastapi import APIRouter


from .account import endpoints as account_endpoints
from .packet import endpoints as packet_endpoints

api_router = APIRouter()

api_router.include_router(
    account_endpoints.router, prefix="/account", tags=["Account"]
)
api_router.include_router(
    packet_endpoints.router, prefix="/packet", tags=["Packet"]
)
