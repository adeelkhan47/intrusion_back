from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from fastapi import Request

from api.packet.schemas import GetPackets
from model import Packet
from helpers.jwt import decode_token

router = APIRouter()


@router.get("", response_model=GetPackets)
def FetchPackets(request: Request,token: str):
    id , _ = decode_token(token)
    if id:
        packets, count = Packet.filter_and_order({})
        return {"packets": packets, "count": count}
    raise HTTPException(status_code=404, detail="Not Found.")
