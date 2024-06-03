from datetime import datetime, timedelta

from fastapi_sqlalchemy import db
from sqlalchemy import Column, String, JSON, Boolean,Float
from sqlalchemy.orm import relationship

from .base import Base


class Packet(Base):
    __tablename__ = "packet"

    intrusion = Column(Boolean, default=False)
    label = Column(String, nullable=False)
    accuracy = Column(Float, nullable=False,default=0)
