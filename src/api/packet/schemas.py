from typing import List, Optional

from pydantic import BaseModel



class Packet(BaseModel):
    id: int
    intrusion: bool
    label: str
    accuracy: float
    class Config:
        orm_mode = True
class GetPackets(BaseModel):
    packets: List[Packet]
    count: int

    class Config:
        orm_mode = True
