from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class Tool(Base):
    __tablename__ = "tools"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    repo_url = Column(Text, unique=True, nullable=False)
    description = Column(Text)
    main_script = Column(String(100))
    category = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="tool")

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    identity = Column(String(255), nullable=False)
    type = Column(String(50))
    tags = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="target")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    tool_id = Column(Integer, ForeignKey("tools.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    raw_output = Column(Text)
    ai_analysis = Column(Text)
    status = Column(String(20))
    executed_at = Column(DateTime, default=datetime.utcnow)
    tool = relationship("Tool", back_populates="scans")
    target = relationship("Target", back_populates="scans")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(255), nullable=False)
    source = Column(String(50))
    details = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
