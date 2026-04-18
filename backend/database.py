from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import Settings


class Base(DeclarativeBase):
    pass


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), nullable=False)
    target = Column(String(255), nullable=False)
    tool_name = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    parameters = Column(Text, default="{}")
    findings = Column(Text, default="{}")
    raw_output = Column(Text)
    execution_time = Column(Float)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    network_sent = Column(Integer)
    network_received = Column(Integer)
    exit_code = Column(Integer)
    error_message = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)


class ToolDefinition(Base):
    __tablename__ = "tool_definitions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(50), unique=True, nullable=False)
    docker_image = Column(String(255), nullable=False)
    timeout = Column(Integer, default=300)
    allowed_parameters = Column(Text)
    dangerous_flags = Column(Text)
    description = Column(Text)
    use_cases = Column(Text)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime)


class ExecutionLog(Base):
    __tablename__ = "execution_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    log_level = Column(String(10))
    message = Column(Text)


class WorkflowStep(Base):
    __tablename__ = "workflow_steps"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    parent_step_id = Column(String(36), ForeignKey("workflow_steps.id"), nullable=True)
    execution_order = Column(Integer, nullable=False, default=0)
    tool_name = Column(String(50), nullable=False)
    confidence = Column(Float, default=0.0)
    parameters = Column(Text, default="{}")
    findings = Column(Text, default="[]")
    raw_output = Column(Text)
    execution_time = Column(Float)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    exit_code = Column(Integer)
    status = Column(String(20), nullable=False, default="pending")
    error_message = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime)


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    step_id = Column(String(36), ForeignKey("workflow_steps.id"), nullable=True)
    anomaly_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(Float, default=0.0)
    details = Column(Text, default="{}")
    suggestion = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Engine and session factory
engine = create_engine(Settings.DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _seed_tool_definitions()


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


TOOL_SEED_DATA = [
    {"name": "nmap", "docker_image": "nmap", "description": "Port scanning, service discovery", "use_cases": '["port scanning", "service detection", "OS fingerprinting"]', "dangerous_flags": '["-T5", "-T4", "--script=exploit"]', "timeout": 300},
    {"name": "masscan", "docker_image": "masscan", "description": "Fast mass port scanning", "use_cases": '["mass scanning", "large network enumeration"]', "dangerous_flags": '["--rate=10000"]', "timeout": 300},
    {"name": "nikto", "docker_image": "nikto", "description": "Web server vulnerability scanning", "use_cases": '["web vulnerability scanning", "server misconfiguration"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "sqlmap", "docker_image": "sqlmap", "description": "SQL injection testing", "use_cases": '["SQL injection", "database enumeration"]', "dangerous_flags": '["--os-shell", "--os-pwn"]', "timeout": 600},
    {"name": "ffuf", "docker_image": "ffuf", "description": "Web fuzzing, endpoint discovery", "use_cases": '["fuzzing", "endpoint discovery", "parameter brute-forcing"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "gobuster", "docker_image": "gobuster", "description": "Directory and DNS enumeration", "use_cases": '["directory brute-forcing", "DNS enumeration", "vhost discovery"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "hydra", "docker_image": "hydra", "description": "Credential brute-forcing", "use_cases": '["password brute-forcing", "credential testing"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "john", "docker_image": "john", "description": "Password hash cracking", "use_cases": '["hash cracking", "password recovery"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "curl", "docker_image": "curl", "description": "Web requests, API testing", "use_cases": '["HTTP requests", "API testing", "header inspection"]', "dangerous_flags": '[]', "timeout": 120},
    {"name": "tcpdump", "docker_image": "tcpdump", "description": "Packet capture and analysis", "use_cases": '["packet capture", "traffic analysis"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "nuclei", "docker_image": "nuclei", "description": "Template-based vulnerability scanning", "use_cases": '["vulnerability scanning", "CVE detection", "template-based scanning"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "hashcat", "docker_image": "hashcat", "description": "Advanced password hash cracking", "use_cases": '["hash cracking", "password recovery", "GPU-accelerated cracking"]', "dangerous_flags": '[]', "timeout": 3600},
    {"name": "gitleaks", "docker_image": "gitleaks", "description": "Git repository secret scanning", "use_cases": '["secret detection", "API key scanning", "credential leak detection"]', "dangerous_flags": '[]', "timeout": 300},
]


def _seed_tool_definitions() -> None:
    db = SessionLocal()
    try:
        existing = db.query(ToolDefinition).count()
        if existing > 0:
            return
        for tool_data in TOOL_SEED_DATA:
            db.add(ToolDefinition(**tool_data))
        db.commit()
    finally:
        db.close()
