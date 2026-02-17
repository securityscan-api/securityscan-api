import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, JSON
from app.db.database import Base


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, nullable=False)
    api_key_hash = Column(String, unique=True, nullable=False)
    plan = Column(String, nullable=False, default="FREE")
    stripe_customer_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    skill_url = Column(String, nullable=False)
    score = Column(Integer, nullable=False)
    recommendation = Column(String, nullable=False)
    issues_json = Column(JSON, nullable=True)
    scan_time_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class UsageLog(Base):
    __tablename__ = "usage_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)
    billed = Column(Boolean, default=False)
    amount_cents = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Certification(Base):
    __tablename__ = "certifications"

    id = Column(String, primary_key=True, default=generate_uuid)
    skill_url = Column(String, unique=True, nullable=False)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    score = Column(Integer, nullable=False)
    cert_hash = Column(String, nullable=False)
    certified_at = Column(DateTime, default=datetime.utcnow)
