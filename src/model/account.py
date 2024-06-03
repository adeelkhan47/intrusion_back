from datetime import datetime, timedelta

from fastapi_sqlalchemy import db
from sqlalchemy import Column, String, JSON, Boolean
from sqlalchemy.orm import relationship

from .base import Base


class Account(Base):
    __tablename__ = "account"

    username = Column(String, index=True, nullable=False, unique=True)
    password = Column(String, nullable=False)
    @classmethod
    def get_by_username(cls, username: str):
        row = db.session.query(cls).filter_by(username=username).first()
        return row

    @classmethod
    def get_by_username_pass(cls, username: str, password: str):
        row = db.session.query(cls).filter_by(username=username, password=password).first()
        return row

