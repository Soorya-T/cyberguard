"""
Database Session Management Module
==================================

Responsible for:
- Creating database engine with optimized settings
- Managing session lifecycle
- Providing dependency for FastAPI routes
- Handling PostgreSQL-specific optimizations
- Connection pooling configuration

Security Features:
- Connection validation (pool_pre_ping)
- Proper session cleanup
- Transaction isolation
"""

from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool

from app.core.config import settings
from app.core.logging import get_logger

# Initialize logger
logger = get_logger(__name__)


# ==========================
# Database Engine
# ==========================

engine = create_engine(
    settings.DATABASE_URL,
    # Connection Pool Settings
    poolclass=QueuePool,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=settings.DB_POOL_RECYCLE,
    pool_pre_ping=True,  # Validate connections before use
    
    # SQLAlchemy 2.0 Style
    future=True,
    
    # Echo SQL in debug mode
    echo=settings.DEBUG,
    
    # Connection arguments
    connect_args={
        "connect_timeout": 10,
        "application_name": "cyberguard-backend",
    },
)


# ==========================
# Pool Event Listeners
# ==========================

@event.listens_for(engine, "connect")
def receive_connect(dbapi_connection, connection_record):
    """Log new database connections."""
    logger.debug(
        "New database connection established",
        extra={"event": "db_connect"}
    )


@event.listens_for(engine, "checkout")
def receive_checkout(dbapi_connection, connection_record, connection_proxy):
    """Log connection checkout from pool."""
    logger.debug(
        "Database connection checked out from pool",
        extra={"event": "db_checkout"}
    )


@event.listens_for(engine, "checkin")
def receive_checkin(dbapi_connection, connection_record):
    """Log connection return to pool."""
    logger.debug(
        "Database connection returned to pool",
        extra={"event": "db_checkin"}
    )


# ==========================
# Session Factory
# ==========================

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,  # Better performance, access objects after commit
)


# ==========================
# Dependency for FastAPI
# ==========================

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session.
    
    Ensures:
    - Session is opened per request
    - Session is properly closed after request completes
    - Transactions are rolled back on error
    
    Yields:
        SQLAlchemy Session object
        
    Usage:
        @router.get("/users")
        def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(
            "Database session error",
            extra={"error": str(e)}
        )
        db.rollback()
        raise
    finally:
        db.close()


# ==========================
# Database Health Check
# ==========================

def check_database_connection() -> bool:
    """
    Check if database connection is healthy.
    
    Returns:
        True if connection is healthy, False otherwise
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(
            "Database health check failed",
            extra={"error": str(e)}
        )
        return False


# ==========================
# Database Utilities
# ==========================

def get_db_session() -> Session:
    """
    Get a database session for non-FastAPI contexts.
    
    Use this for background tasks, scripts, etc.
    Remember to close the session when done.
    
    Returns:
        SQLAlchemy Session object
        
    Usage:
        db = get_db_session()
        try:
            # Do work
            db.commit()
        finally:
            db.close()
    """
    return SessionLocal()
