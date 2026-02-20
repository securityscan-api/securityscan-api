from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import get_settings

settings = get_settings()

# Configure engine based on database type
connect_args = {}
if settings.database_url.startswith("sqlite"):
    # SQLite requires check_same_thread=False for FastAPI
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,  # Verify connections are alive
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency that provides a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """Context manager version for non-FastAPI usage."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
