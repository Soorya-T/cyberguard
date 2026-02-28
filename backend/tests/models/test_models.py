"""
Model Unit Tests
================

Tests for SQLAlchemy models including:
- User model
- Organization model
- Role enum
"""

import pytest
from datetime import datetime, UTC
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.models.user import User
from app.models.organization import Organization
from app.models.role_enum import Role
from app.services.auth_service import AuthService


pytestmark = pytest.mark.unit


class TestRoleEnum:
    """Tests for Role enum."""
    
    def test_role_has_super_admin(self):
        """Test that SUPER_ADMIN role exists."""
        assert hasattr(Role, "SUPER_ADMIN")
        assert Role.SUPER_ADMIN.value == "SUPER_ADMIN"
    
    def test_role_has_org_admin(self):
        """Test that ORG_ADMIN role exists."""
        assert hasattr(Role, "ORG_ADMIN")
        assert Role.ORG_ADMIN.value == "ORG_ADMIN"
    
    def test_role_has_security_analyst(self):
        """Test that SECURITY_ANALYST role exists."""
        assert hasattr(Role, "SECURITY_ANALYST")
        assert Role.SECURITY_ANALYST.value == "SECURITY_ANALYST"
    
    def test_role_has_read_only(self):
        """Test that READ_ONLY role exists."""
        assert hasattr(Role, "READ_ONLY")
        assert Role.READ_ONLY.value == "READ_ONLY"
    
    def test_role_count(self):
        """Test that there are exactly 4 roles."""
        roles = list(Role)
        assert len(roles) == 4
    
    def test_role_is_string_enum(self):
        """Test that Role is a string enum."""
        assert isinstance(Role.SUPER_ADMIN, str)
        assert Role.SUPER_ADMIN == "SUPER_ADMIN"
    
    def test_role_can_be_created_from_string(self):
        """Test that Role can be created from string value."""
        role = Role("SUPER_ADMIN")
        assert role == Role.SUPER_ADMIN


class TestUserModel:
    """Tests for User model."""
    
    def test_user_creation(self, db_session: Session, sample_organization: Organization):
        """Test creating a user instance."""
        # Arrange
        auth_service = AuthService(db_session)
        user_id = uuid4()
        
        # Act
        user = User(
            id=user_id,
            email="test@example.com",
            hashed_password=auth_service.hash_password("TestPassword123!"),
            role=Role.READ_ONLY,
            tenant_id=sample_organization.id,
        )
        db_session.add(user)
        db_session.commit()
        
        # Assert
        saved_user = db_session.query(User).filter(User.id == user_id).first()
        assert saved_user is not None
        assert saved_user.email == "test@example.com"
    
    def test_user_default_role(self, db_session: Session, sample_organization: Organization):
        """Test that default role is READ_ONLY."""
        # Arrange & Act
        user = User(
            id=uuid4(),
            email="default@example.com",
            hashed_password="hashed",
            tenant_id=sample_organization.id,
        )
        
        # Assert
        assert user.role == Role.READ_ONLY
    
    def test_user_default_is_active(self, db_session: Session, sample_organization: Organization):
        """Test that user is active by default."""
        # Arrange & Act
        user = User(
            id=uuid4(),
            email="active@example.com",
            hashed_password="hashed",
            tenant_id=sample_organization.id,
        )
        
        # Assert
        assert user.is_active is True
    
    def test_user_default_is_locked(self, db_session: Session, sample_organization: Organization):
        """Test that user is not locked by default."""
        # Arrange & Act
        user = User(
            id=uuid4(),
            email="unlocked@example.com",
            hashed_password="hashed",
            tenant_id=sample_organization.id,
        )
        
        # Assert
        assert user.is_locked is False
    
    def test_user_default_failed_attempts(self, db_session: Session, sample_organization: Organization):
        """Test that failed_attempts is 0 by default."""
        # Arrange & Act
        user = User(
            id=uuid4(),
            email="attempts@example.com",
            hashed_password="hashed",
            tenant_id=sample_organization.id,
        )
        
        # Assert
        assert user.failed_attempts == 0
    
    def test_user_default_token_version(self, db_session: Session, sample_organization: Organization):
        """Test that token_version is 1 by default."""
        # Arrange & Act
        user = User(
            id=uuid4(),
            email="version@example.com",
            hashed_password="hashed",
            tenant_id=sample_organization.id,
        )
        
        # Assert
        assert user.token_version == 1
    
    def test_user_is_authenticated_property(self, sample_user: User):
        """Test is_authenticated property returns True."""
        # Assert
        assert sample_user.is_authenticated is True
    
    def test_user_lock_account(self, sample_user: User, db_session: Session):
        """Test lock_account method."""
        # Arrange
        assert sample_user.is_locked is False
        
        # Act
        sample_user.lock_account()
        db_session.commit()
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.is_locked is True
    
    def test_user_unlock_account(self, sample_locked_user: User, db_session: Session):
        """Test unlock_account method."""
        # Arrange
        assert sample_locked_user.is_locked is True
        
        # Act
        sample_locked_user.unlock_account()
        db_session.commit()
        
        # Assert
        db_session.refresh(sample_locked_user)
        assert sample_locked_user.is_locked is False
        assert sample_locked_user.failed_attempts == 0
    
    def test_user_increment_failed_attempts(self, sample_user: User, db_session: Session):
        """Test increment_failed_attempts method."""
        # Arrange
        initial_attempts = sample_user.failed_attempts
        
        # Act
        should_lock = sample_user.increment_failed_attempts(max_attempts=5)
        db_session.commit()
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == initial_attempts + 1
        assert should_lock is False
    
    def test_user_increment_failed_attempts_locks_at_max(self, sample_user: User, db_session: Session):
        """Test that account locks at max failed attempts."""
        # Arrange
        sample_user.failed_attempts = 4  # One below max
        
        # Act
        should_lock = sample_user.increment_failed_attempts(max_attempts=5)
        db_session.commit()
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == 5
        assert should_lock is True
        assert sample_user.is_locked is True
    
    def test_user_reset_failed_attempts(self, sample_user: User, db_session: Session):
        """Test reset_failed_attempts method."""
        # Arrange
        sample_user.failed_attempts = 3
        db_session.commit()
        
        # Act
        sample_user.reset_failed_attempts()
        db_session.commit()
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == 0
    
    def test_user_invalidate_tokens(self, sample_user: User, db_session: Session):
        """Test invalidate_tokens method."""
        # Arrange
        initial_version = sample_user.token_version
        
        # Act
        sample_user.invalidate_tokens()
        db_session.commit()
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.token_version == initial_version + 1
    
    def test_user_to_dict(self, sample_user: User):
        """Test to_dict method."""
        # Act
        user_dict = sample_user.to_dict()
        
        # Assert
        assert "id" in user_dict
        assert "email" in user_dict
        assert "role" in user_dict
        assert "tenant_id" in user_dict
        assert "is_active" in user_dict
        assert "is_locked" in user_dict
        assert "hashed_password" not in user_dict  # Sensitive data excluded
    
    def test_user_repr(self, sample_user: User):
        """Test __repr__ method."""
        # Act
        repr_str = repr(sample_user)
        
        # Assert
        assert "User" in repr_str
        assert str(sample_user.id) in repr_str or sample_user.email in repr_str
    
    def test_user_organization_relationship(self, sample_user: User, sample_organization: Organization):
        """Test user-organization relationship."""
        # Assert
        assert sample_user.organization.id == sample_organization.id
        assert sample_user.tenant_id == sample_organization.id
    
    def test_user_created_at_auto_set(self, sample_user: User):
        """Test that created_at is automatically set."""
        # Assert
        assert sample_user.created_at is not None
        assert isinstance(sample_user.created_at, datetime)
    
    def test_user_updated_at_auto_set(self, sample_user: User):
        """Test that updated_at is automatically set."""
        # Assert
        assert sample_user.updated_at is not None
        assert isinstance(sample_user.updated_at, datetime)


class TestOrganizationModel:
    """Tests for Organization model."""
    
    def test_organization_creation(self, db_session: Session):
        """Test creating an organization instance."""
        # Arrange
        org_id = uuid4()
        
        # Act
        org = Organization(
            id=org_id,
            name="Test Corp",
        )
        db_session.add(org)
        db_session.commit()
        
        # Assert
        saved_org = db_session.query(Organization).filter(Organization.id == org_id).first()
        assert saved_org is not None
        assert saved_org.name == "Test Corp"
    
    def test_organization_unique_name(self, db_session: Session, sample_organization: Organization):
        """Test that organization names must be unique."""
        # Arrange
        duplicate_org = Organization(
            id=uuid4(),
            name=sample_organization.name,  # Same name
        )
        
        # Act & Assert
        db_session.add(duplicate_org)
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()
    
    def test_organization_user_count(self, sample_organization: Organization, sample_user: User):
        """Test user_count property."""
        # Assert
        assert sample_organization.user_count >= 1
    
    def test_organization_to_dict(self, sample_organization: Organization):
        """Test to_dict method."""
        # Act
        org_dict = sample_organization.to_dict()
        
        # Assert
        assert "id" in org_dict
        assert "name" in org_dict
        assert "created_at" in org_dict
        assert "user_count" in org_dict
    
    def test_organization_repr(self, sample_organization: Organization):
        """Test __repr__ method."""
        # Act
        repr_str = repr(sample_organization)
        
        # Assert
        assert "Organization" in repr_str
        assert sample_organization.name in repr_str
    
    def test_organization_users_relationship(self, sample_organization: Organization, sample_user: User):
        """Test organization-users relationship."""
        # Assert
        assert len(sample_organization.users) >= 1
        user_ids = [u.id for u in sample_organization.users]
        assert sample_user.id in user_ids
    
    def test_organization_created_at_auto_set(self, sample_organization: Organization):
        """Test that created_at is automatically set."""
        # Assert
        assert sample_organization.created_at is not None
        assert isinstance(sample_organization.created_at, datetime)
    
    def test_organization_updated_at_auto_set(self, sample_organization: Organization):
        """Test that updated_at is automatically set."""
        # Assert
        assert sample_organization.updated_at is not None
        assert isinstance(sample_organization.updated_at, datetime)


class TestUserOrganizationRelationship:
    """Tests for User-Organization relationship."""
    
    def test_user_belongs_to_organization(self, sample_user: User, sample_organization: Organization):
        """Test that user belongs to correct organization."""
        # Assert
        assert sample_user.tenant_id == sample_organization.id
        assert sample_user.organization.id == sample_organization.id
    
    def test_organization_has_users(self, sample_organization: Organization, sample_user: User):
        """Test that organization has users."""
        # Assert
        assert len(sample_organization.users) >= 1
    
    def test_multiple_users_in_organization(
        self,
        sample_organization: Organization,
        sample_user: User,
        sample_org_admin: User,
    ):
        """Test that organization can have multiple users."""
        # Assert
        assert len(sample_organization.users) >= 2
    
    def test_cascade_delete_users_on_organization_delete(
        self,
        db_session: Session,
        sample_organization: Organization,
        sample_user: User,
    ):
        """Test that users are deleted when organization is deleted."""
        # Arrange
        user_id = sample_user.id
        org_id = sample_organization.id
        
        # Act
        db_session.delete(sample_organization)
        db_session.commit()
        
        # Assert
        deleted_user = db_session.query(User).filter(User.id == user_id).first()
        assert deleted_user is None


class TestUserModelValidation:
    """Tests for User model validation."""
    
    def test_user_email_required(self, db_session: Session, sample_organization: Organization):
        """Test that email is required."""
        # Arrange
        user = User(
            id=uuid4(),
            hashed_password="hashed",
            tenant_id=sample_organization.id,
        )
        
        # Act & Assert
        db_session.add(user)
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()
    
    def test_user_tenant_id_required(self, db_session: Session):
        """Test that tenant_id is required."""
        # Arrange
        user = User(
            id=uuid4(),
            email="notenant@example.com",
            hashed_password="hashed",
        )
        
        # Act & Assert
        db_session.add(user)
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()
    
    def test_user_email_unique(self, db_session: Session, sample_user: User, sample_organization: Organization):
        """Test that email must be unique."""
        # Arrange
        duplicate_user = User(
            id=uuid4(),
            email=sample_user.email,  # Same email
            hashed_password="hashed",
            tenant_id=sample_organization.id,
        )
        
        # Act & Assert
        db_session.add(duplicate_user)
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()


class TestOrganizationModelValidation:
    """Tests for Organization model validation."""
    
    def test_organization_name_required(self, db_session: Session):
        """Test that name is required."""
        # Arrange
        org = Organization(id=uuid4())
        
        # Act & Assert
        db_session.add(org)
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()
