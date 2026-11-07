import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from backend.app.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DBScan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    target_name = Column(String(255), nullable=False)
    source_code = Column(Text, nullable=True)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    security_score = Column(Float, default=100.0)
    execution_time_ms = Column(Float, default=0.0)
    
    findings = relationship("DBFinding", back_populates="scan", cascade="all, delete-orphan")

class DBFinding(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id"), index=True)
    name = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False)
    confidence = Column(String(32), nullable=False)
    category = Column(String(128), nullable=False)
    contract_name = Column(String(255), default="Unknown")
    function_name = Column(String(255), default="Global")
    file_path = Column(String(512), default="input.sol")
    line_start = Column(Integer, default=1)
    line_end = Column(Integer, default=1)
    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    reproduction = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)
    tool = Column(String(128), default="Sentinel Core")

    scan = relationship("DBScan", back_populates="findings")

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
