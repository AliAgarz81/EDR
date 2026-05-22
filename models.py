from sqlalchemy import Column, Integer, String, Text
from database import Base

class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String)
    ip = Column(String)
    status = Column(String)
    last_seen = Column(String)

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String)
    category = Column(String)
    content = Column(Text)