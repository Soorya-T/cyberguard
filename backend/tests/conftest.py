"""
Test Configuration and Fixtures
================================

Central configuration for pytest with all shared fixtures.

Features:
- SQLite in-memory database for testing
- TestClient setup
- Fixture for sample users, organizations
- Dependency overrides for database session
"""

import os
import uuid
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

# Set testing environment before importing app modules
os.environ["ENVIRONMENT"] = "testing"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-min-32-chars"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["RATE_LIMIT_ENABLED"] = "false"  # Disable rate limiting in tests

from app.db.base import Base
from app.db.session import get_db
from app.models.user import User
from app.models.organization import Organization
from app.models.role_enum import Role
from app.services.auth_service import AuthService
from app.main import app as main_app


# =====================================
# Database Configuration
# =====================================

# Create in-memory SQLite engine for testing
# StaticPool is used to maintain the same connection across tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

# Enable foreign key constraints for SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key constraints for SQLite."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# =====================================
# Database Fixtures
# =====================================

@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """
    Create a fresh database session for each test.
    
    Creates all tables before each test and drops them after.
    This ensures complete test isolation.
    
    Yields:
        SQLAlchemy Session object
    """
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create session
    session = TestingSessionLocal()
    
    try:
        yield session
    finally:
        session.close()
        # Drop all tables after test
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """
    Create a TestClient with database dependency override.
    
    Args:
        db_session: Database session fixture
        
    Yields:
        TestClient instance
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    
    main_app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(main_app) as test_client:
        yield test_client
    
    main_app.dependency_overrides.clear()


# =====================================
# Organization Fixtures
# =====================================

@pytest.fixture
def sample_organization(db_session: Session) -> Organization:
    """
    Create a sample organization for testing.
    
    Args:
        db_session: Database session
        
    Returns:
        Organization instance
    """
    org = Organization(
        id=uuid.uuid4(),
        name="Test Organization",
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.fixture
def second_organization(db_session: Session) -> Organization:
    """
    Create a second organization for cross-tenant testing.
    
    Args:
        db_session: Database session
        
    Returns:
        Organization instance
    """
    org = Organization(
        id=uuid.uuid4(),
        name="Second Organization",
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


# =====================================
# User Fixtures
# =====================================

@pytest.fixture
def sample_user(db_session: Session, sample_organization: Organization) -> User:
    """
    Create a sample regular user for testing.
    
    Args:
        db_session: Database session
        sample_organization: Organization fixture
        
    Returns:
        User instance with READ_ONLY role
    """
    auth_service = AuthService(db_session)
    hashed_password = auth_service.hash_password("TestPassword123!")
    
    user = User(
        id=uuid.uuid4(),
        email="user@testorg.com",
        hashed_password=hashed_password,
        role=Role.READ_ONLY,
        tenant_id=sample_organization.id,
        is_active=True,
        is_locked=False,
        failed_attempts=0,
        token_version=1,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_analyst(db_session: Session, sample_organization: Organization) -> User:
    """
    Create a sample security analyst for testing.
    
    Args:
        db_session: Database session
        sample_organization: Organization fixture
        
    Returns:
        User instance with SECURITY_ANALYST role
    """
    auth_service = AuthService(db_session)
    hashed_password = auth_service.hash_password("AnalystPassword123!")
    
    user = User(
        id=uuid.uuid4(),
        email="analyst@testorg.com",
        hashed_password=hashed_password,
        role=Role.SECURITY_ANALYST,
        tenant_id=sample_organization.id,
        is_active=True,
        is_locked=False,
        failed_attempts=0,
        token_version=1,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_org_admin(db_session: Session, sample_organization: Organization) -> User:
    """
    Create a sample organization admin for testing.
    
    Args:
        db_session: Database session
        sample_organization: Organization fixture
        
    Returns:
        User instance with ORG_ADMIN role
    """
    auth_service = AuthService(db_session)
    hashed_password = auth_service.hash_password("AdminPassword123!")
    
    user = User(
        id=uuid.uuid4(),
        email="admin@testorg.com",
        hashed_password=hashed_password,
        role=Role.ORG_ADMIN,
        tenant_id=sample_organization.id,
        is_active=True,
        is_locked=False,
        failed_attempts=0,
        token_version=1,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_super_admin(db_session: Session, sample_organization: Organization) -> User:
    """
    Create a sample super admin for testing.
    
    Args:
        db_session: Database session
        sample_organization: Organization fixture
        
    Returns:
        User instance with SUPER_ADMIN role
    """
    auth_service = AuthService(db_session)
    hashed_password = auth_service.hash_password("SuperAdminPassword123!")
    
    user = User(
        id=uuid.uuid4(),
        email="superadmin@testorg.com",
        hashed_password=hashed_password,
        role=Role.SUPER_ADMIN,
        tenant_id=sample_organization.id,
        is_active=True,
        is_locked=False,
        failed_attempts=0,
        token_version=1,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_locked_user(db_session: Session, sample_organization: Organization) -> User:
    """
    Create a sample locked user for testing.
    
    Args:
        db_session: Database session
        sample_organization: Organization fixture
        
    Returns:
        User instance with locked account
    """
    auth_service = AuthService(db_session)
    hashed_password = auth_service.hash_password("LockedUserPassword123!")
    
    user = User(
        id=uuid.uuid4(),
        email="locked@testorg.com",
        hashed_password=hashed_password,
        role=Role.READ_ONLY,
        tenant_id=sample_organization.id,
        is_active=True,
        is_locked=True,
        failed_attempts=5,
        token_version=1,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_inactive_user(db_session: Session, sample_organization: Organization) -> User:
    """
    Create a sample inactive user for testing.
    
    Args:
        db_session: Database session
        sample_organization: Organization fixture
        
    Returns:
        User instance with inactive account
    """
    auth_service = AuthService(db_session)
    hashed_password = auth_service.hash_password("InactiveUserPassword123!")
    
    user = User(
        id=uuid.uuid4(),
        email="inactive@testorg.com",
        hashed_password=hashed_password,
        role=Role.READ_ONLY,
        tenant_id=sample_organization.id,
        is_active=False,
        is_locked=False,
        failed_attempts=0,
        token_version=1,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def second_org_user(db_session: Session, second_organization: Organization) -> User:
    """
    Create a user in a different organization for cross-tenant testing.
    
    Args:
        db_session: Database session
        second_organization: Second organization fixture
        
    Returns:
        User instance in different organization
    """
    auth_service = AuthService(db_session)
    hashed_password = auth_service.hash_password("SecondOrgPassword123!")
    
    user = User(
        id=uuid.uuid4(),
        email="user@secondorg.com",
        hashed_password=hashed_password,
        role=Role.READ_ONLY,
        tenant_id=second_organization.id,
        is_active=True,
        is_locked=False,
        failed_attempts=0,
        token_version=1,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# =====================================
# Token Fixtures
# =====================================

@pytest.fixture
def user_access_token(sample_user: User) -> str:
    """
    Generate an access token for the sample user.
    
    Args:
        sample_user: User fixture
        
    Returns:
        JWT access token string
    """
    return AuthService.create_access_token(
        user_id=sample_user.id,
        tenant_id=sample_user.tenant_id,
        token_version=sample_user.token_version,
    )


@pytest.fixture
def user_refresh_token(sample_user: User) -> str:
    """
    Generate a refresh token for the sample user.
    
    Args:
        sample_user: User fixture
        
    Returns:
        JWT refresh token string
    """
    return AuthService.create_refresh_token(
        user_id=sample_user.id,
        tenant_id=sample_user.tenant_id,
        token_version=sample_user.token_version,
    )


@pytest.fixture
def super_admin_access_token(sample_super_admin: User) -> str:
    """
    Generate an access token for the super admin user.
    
    Args:
        sample_super_admin: Super admin fixture
        
    Returns:
        JWT access token string
    """
    return AuthService.create_access_token(
        user_id=sample_super_admin.id,
        tenant_id=sample_super_admin.tenant_id,
        token_version=sample_super_admin.token_version,
    )


@pytest.fixture
def org_admin_access_token(sample_org_admin: User) -> str:
    """
    Generate an access token for the org admin user.
    
    Args:
        sample_org_admin: Org admin fixture
        
    Returns:
        JWT access token string
    """
    return AuthService.create_access_token(
        user_id=sample_org_admin.id,
        tenant_id=sample_org_admin.tenant_id,
        token_version=sample_org_admin.token_version,
    )


@pytest.fixture
def analyst_access_token(sample_analyst: User) -> str:
    """
    Generate an access token for the analyst user.
    
    Args:
        sample_analyst: Analyst fixture
        
    Returns:
        JWT access token string
    """
    return AuthService.create_access_token(
        user_id=sample_analyst.id,
        tenant_id=sample_analyst.tenant_id,
        token_version=sample_analyst.token_version,
    )


# =====================================
# Auth Header Fixtures
# =====================================

@pytest.fixture
def auth_headers(user_access_token: str) -> dict:
    """
    Create authorization headers for the sample user.
    
    Args:
        user_access_token: Access token fixture
        
    Returns:
        Dictionary with Authorization header
    """
    return {"Authorization": f"Bearer {user_access_token}"}


@pytest.fixture
def super_admin_auth_headers(super_admin_access_token: str) -> dict:
    """
    Create authorization headers for the super admin user.
    
    Args:
        super_admin_access_token: Super admin access token fixture
        
    Returns:
        Dictionary with Authorization header
    """
    return {"Authorization": f"Bearer {super_admin_access_token}"}


@pytest.fixture
def org_admin_auth_headers(org_admin_access_token: str) -> dict:
    """
    Create authorization headers for the org admin user.
    
    Args:
        org_admin_access_token: Org admin access token fixture
        
    Returns:
        Dictionary with Authorization header
    """
    return {"Authorization": f"Bearer {org_admin_access_token}"}


@pytest.fixture
def analyst_auth_headers(analyst_access_token: str) -> dict:
    """
    Create authorization headers for the analyst user.
    
    Args:
        analyst_access_token: Analyst access token fixture
        
    Returns:
        Dictionary with Authorization header
    """
    return {"Authorization": f"Bearer {analyst_access_token}"}


# =====================================
# Utility Fixtures
# =====================================

@pytest.fixture
def test_password() -> str:
    """Return a test password that meets all requirements."""
    return "TestPassword123!"


@pytest.fixture
def weak_password() -> str:
    """Return a weak password for validation testing."""
    return "weak"


@pytest.fixture
def valid_email() -> str:
    """Return a valid test email."""
    return "test@example.com"
