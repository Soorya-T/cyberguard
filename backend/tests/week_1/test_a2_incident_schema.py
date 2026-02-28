"""
A2 – Incident Schema, Lifecycle States & SLA Tracking Tests
============================================================

Tests for:
- Incident model schema design (columns, types, defaults)
- Lifecycle states (OPEN, REVIEW, CLOSED) via IncidentStatus enum
- Lifecycle transition validation (lifecycle_service)
- SLA timestamp tracking fields (sla_due_at, first_response_at, closed_at, sla_breached)
- SLA breach detection (sla_service)
- SLA deadline calculation (core/sla.py)
"""

from datetime import datetime, timedelta, UTC
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.core.enums import IncidentStatus
from app.core.sla import SLA_HOURS, calculate_sla_due
from app.models.incident import Incident
from app.models.security_event import SecurityEvent
from app.services.lifecycle_service import VALID_TRANSITIONS, validate_transition
from app.services.sla_service import check_sla_breach


# =============================================
# IncidentStatus Enum Tests
# =============================================


class TestIncidentStatusEnum:
    """Validate the IncidentStatus lifecycle enum."""

    def test_open_status_exists(self):
        """OPEN should be a valid IncidentStatus."""
        assert IncidentStatus.OPEN == "OPEN"

    def test_review_status_exists(self):
        """REVIEW should be a valid IncidentStatus."""
        assert IncidentStatus.REVIEW == "REVIEW"

    def test_closed_status_exists(self):
        """CLOSED should be a valid IncidentStatus."""
        assert IncidentStatus.CLOSED == "CLOSED"

    def test_enum_has_exactly_three_states(self):
        """IncidentStatus should have exactly 3 lifecycle states."""
        assert len(IncidentStatus) == 3

    def test_enum_values_are_strings(self):
        """All IncidentStatus values should be strings."""
        for status in IncidentStatus:
            assert isinstance(status.value, str)

    def test_enum_is_str_subclass(self):
        """IncidentStatus should be a str enum for JSON serialization."""
        assert issubclass(IncidentStatus, str)


# =============================================
# Lifecycle Transition Validation Tests
# =============================================


class TestLifecycleTransitions:
    """Validate lifecycle state transition rules."""

    def test_valid_transitions_mapping_exists(self):
        """VALID_TRANSITIONS should define allowed transitions for each state."""
        assert "OPEN" in VALID_TRANSITIONS
        assert "REVIEW" in VALID_TRANSITIONS
        assert "CLOSED" in VALID_TRANSITIONS

    def test_open_to_review_allowed(self):
        """OPEN -> REVIEW should be a valid transition."""
        # Should not raise
        validate_transition("OPEN", "REVIEW")

    def test_review_to_closed_allowed(self):
        """REVIEW -> CLOSED should be a valid transition."""
        validate_transition("REVIEW", "CLOSED")

    def test_open_to_closed_rejected(self):
        """OPEN -> CLOSED should be rejected (must go through REVIEW)."""
        with pytest.raises(HTTPException) as exc_info:
            validate_transition("OPEN", "CLOSED")
        assert exc_info.value.status_code == 400

    def test_closed_to_open_rejected(self):
        """CLOSED -> OPEN should be rejected (no re-opening)."""
        with pytest.raises(HTTPException) as exc_info:
            validate_transition("CLOSED", "OPEN")
        assert exc_info.value.status_code == 400

    def test_closed_to_review_rejected(self):
        """CLOSED -> REVIEW should be rejected."""
        with pytest.raises(HTTPException) as exc_info:
            validate_transition("CLOSED", "REVIEW")
        assert exc_info.value.status_code == 400

    def test_review_to_open_rejected(self):
        """REVIEW -> OPEN should be rejected (no backward transitions)."""
        with pytest.raises(HTTPException) as exc_info:
            validate_transition("REVIEW", "OPEN")
        assert exc_info.value.status_code == 400

    def test_same_state_transition_rejected(self):
        """Transitioning to the same state should be rejected."""
        with pytest.raises(HTTPException) as exc_info:
            validate_transition("OPEN", "OPEN")
        assert exc_info.value.status_code == 400

    def test_invalid_current_status_rejected(self):
        """Unknown current status should raise HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            validate_transition("UNKNOWN", "OPEN")
        assert exc_info.value.status_code == 400

    def test_closed_has_no_valid_transitions(self):
        """CLOSED state should have no valid outgoing transitions."""
        assert VALID_TRANSITIONS["CLOSED"] == []


# =============================================
# Incident Model Schema Tests
# =============================================


class TestIncidentModelSchema:
    """Validate the Incident ORM model columns and types."""

    def test_incident_table_name(self):
        """Incident model should map to 'incidents' table."""
        assert Incident.__tablename__ == "incidents"

    def test_incident_has_id_column(self):
        """Incident should have an 'id' primary key column."""
        assert hasattr(Incident, "id")

    def test_incident_has_src_user_column(self):
        """Incident should have a 'src_user' column."""
        assert hasattr(Incident, "src_user")

    def test_incident_has_dst_user_column(self):
        """Incident should have a 'dst_user' column."""
        assert hasattr(Incident, "dst_user")

    def test_incident_has_subject_column(self):
        """Incident should have a 'subject' column."""
        assert hasattr(Incident, "subject")

    def test_incident_has_ip_address_column(self):
        """Incident should have an 'ip_address' column."""
        assert hasattr(Incident, "ip_address")

    def test_incident_has_status_column(self):
        """Incident should have a 'status' column."""
        assert hasattr(Incident, "status")

    def test_incident_has_risk_score_column(self):
        """Incident should have a 'risk_score' column."""
        assert hasattr(Incident, "risk_score")

    def test_incident_has_classification_column(self):
        """Incident should have a 'classification' column."""
        assert hasattr(Incident, "classification")

    def test_incident_has_explanation_column(self):
        """Incident should have an 'explanation' column."""
        assert hasattr(Incident, "explanation")

    def test_incident_has_created_at_column(self):
        """Incident should have a 'created_at' column."""
        assert hasattr(Incident, "created_at")

    def test_incident_has_processed_at_column(self):
        """Incident should have a 'processed_at' column."""
        assert hasattr(Incident, "processed_at")


# =============================================
# SecurityEvent Model Schema Tests
# =============================================


class TestSecurityEventModelSchema:
    """Validate the SecurityEvent ORM model for SLA tracking."""

    def test_security_event_table_name(self):
        """SecurityEvent should map to 'security_events' table."""
        assert SecurityEvent.__tablename__ == "security_events"

    def test_security_event_has_id(self):
        """SecurityEvent should have an 'id' column."""
        assert hasattr(SecurityEvent, "id")

    def test_security_event_has_tenant_id(self):
        """SecurityEvent should have a 'tenant_id' column for multi-tenancy."""
        assert hasattr(SecurityEvent, "tenant_id")

    def test_security_event_has_status(self):
        """SecurityEvent should have a 'status' column for lifecycle state."""
        assert hasattr(SecurityEvent, "status")

    def test_security_event_has_created_at(self):
        """SecurityEvent should have a 'created_at' timestamp."""
        assert hasattr(SecurityEvent, "created_at")

    def test_security_event_has_sla_due_at(self):
        """SecurityEvent should have an 'sla_due_at' field for SLA deadline."""
        assert hasattr(SecurityEvent, "sla_due_at")

    def test_security_event_has_first_response_at(self):
        """SecurityEvent should have 'first_response_at' for MTTR tracking."""
        assert hasattr(SecurityEvent, "first_response_at")

    def test_security_event_has_closed_at(self):
        """SecurityEvent should have 'closed_at' for resolution tracking."""
        assert hasattr(SecurityEvent, "closed_at")

    def test_security_event_has_sla_breached(self):
        """SecurityEvent should have 'sla_breached' boolean flag."""
        assert hasattr(SecurityEvent, "sla_breached")


# =============================================
# SLA Calculation Tests
# =============================================


class TestSLACalculation:
    """Test SLA deadline calculation from severity."""

    def test_sla_hours_mapping_exists(self):
        """SLA_HOURS should define hours for each severity level."""
        assert "LOW" in SLA_HOURS
        assert "MEDIUM" in SLA_HOURS
        assert "HIGH" in SLA_HOURS
        assert "CRITICAL" in SLA_HOURS

    def test_critical_sla_is_2_hours(self):
        """CRITICAL severity should have a 2-hour SLA."""
        assert SLA_HOURS["CRITICAL"] == 2

    def test_high_sla_is_8_hours(self):
        """HIGH severity should have an 8-hour SLA."""
        assert SLA_HOURS["HIGH"] == 8

    def test_medium_sla_is_24_hours(self):
        """MEDIUM severity should have a 24-hour SLA."""
        assert SLA_HOURS["MEDIUM"] == 24

    def test_low_sla_is_48_hours(self):
        """LOW severity should have a 48-hour SLA."""
        assert SLA_HOURS["LOW"] == 48

    def test_calculate_sla_due_critical(self):
        """calculate_sla_due('CRITICAL') should return ~2 hours from now."""
        before = datetime.now(UTC)
        due = calculate_sla_due("CRITICAL")
        after = datetime.now(UTC)

        assert before + timedelta(hours=2) <= due <= after + timedelta(hours=2)

    def test_calculate_sla_due_high(self):
        """calculate_sla_due('HIGH') should return ~8 hours from now."""
        before = datetime.now(UTC)
        due = calculate_sla_due("HIGH")
        after = datetime.now(UTC)

        assert before + timedelta(hours=8) <= due <= after + timedelta(hours=8)

    def test_calculate_sla_due_medium(self):
        """calculate_sla_due('MEDIUM') should return ~24 hours from now."""
        before = datetime.now(UTC)
        due = calculate_sla_due("MEDIUM")
        after = datetime.now(UTC)

        assert before + timedelta(hours=24) <= due <= after + timedelta(hours=24)

    def test_calculate_sla_due_low(self):
        """calculate_sla_due('LOW') should return ~48 hours from now."""
        before = datetime.now(UTC)
        due = calculate_sla_due("LOW")
        after = datetime.now(UTC)

        assert before + timedelta(hours=48) <= due <= after + timedelta(hours=48)

    def test_calculate_sla_due_unknown_severity_defaults_to_24h(self):
        """Unknown severity should default to 24-hour SLA."""
        before = datetime.now(UTC)
        due = calculate_sla_due("UNKNOWN_SEVERITY")
        after = datetime.now(UTC)

        assert before + timedelta(hours=24) <= due <= after + timedelta(hours=24)

    def test_calculate_sla_due_returns_datetime(self):
        """calculate_sla_due should return a datetime object."""
        result = calculate_sla_due("HIGH")
        assert isinstance(result, datetime)


# =============================================
# SLA Breach Detection Tests
# =============================================


class TestSLABreachDetection:
    """Test the SLA breach detection service."""

    def _make_event(self, status="OPEN", sla_due_at=None, sla_breached=False, first_response_at=None, closed_at=None):
        """Helper to create a mock event object."""
        return SimpleNamespace(
            status=status,
            sla_due_at=sla_due_at,
            sla_breached=sla_breached,
            first_response_at=first_response_at,
            closed_at=closed_at,
        )

    def test_open_event_past_due_is_breached(self):
        """An OPEN event past its SLA deadline should be marked as breached."""
        event = self._make_event(
            status="OPEN",
            sla_due_at=datetime.now(UTC) - timedelta(hours=1),
        )
        check_sla_breach(event)
        assert event.sla_breached is True

    def test_review_event_past_due_is_breached(self):
        """A REVIEW event past its SLA deadline should be marked as breached."""
        event = self._make_event(
            status="REVIEW",
            sla_due_at=datetime.now(UTC) - timedelta(hours=1),
        )
        check_sla_breach(event)
        assert event.sla_breached is True

    def test_open_event_before_due_is_not_breached(self):
        """An OPEN event before its SLA deadline should NOT be marked as breached."""
        event = self._make_event(
            status="OPEN",
            sla_due_at=datetime.now(UTC) + timedelta(hours=5),
        )
        check_sla_breach(event)
        assert event.sla_breached is False

    def test_closed_event_past_due_is_not_breached(self):
        """A CLOSED event should NOT be retroactively marked as breached."""
        event = self._make_event(
            status="CLOSED",
            sla_due_at=datetime.now(UTC) - timedelta(hours=1),
        )
        check_sla_breach(event)
        assert event.sla_breached is False

    def test_already_breached_event_stays_breached(self):
        """An already-breached event should remain breached (idempotent)."""
        event = self._make_event(
            status="OPEN",
            sla_due_at=datetime.now(UTC) - timedelta(hours=1),
            sla_breached=True,
        )
        check_sla_breach(event)
        assert event.sla_breached is True

    def test_event_with_no_sla_due_at_is_not_breached(self):
        """An event with no sla_due_at should not be marked as breached."""
        event = self._make_event(
            status="OPEN",
            sla_due_at=None,
        )
        check_sla_breach(event)
        assert event.sla_breached is False


# =============================================
# Incident Lifecycle Integration Tests (DB)
# =============================================


class TestIncidentLifecycleDB:
    """Test incident lifecycle state changes in the database."""

    def test_incident_status_update_open_to_processing(self, db_session):
        """Incident status can be updated from RECEIVED to PROCESSING."""
        incident = Incident(
            src_user="a@b.com",
            dst_user="c@d.com",
            subject="Lifecycle Test",
            ip_address="1.2.3.4",
        )
        db_session.add(incident)
        db_session.commit()

        assert incident.status == "RECEIVED"

        incident.status = "PROCESSING"
        db_session.commit()
        db_session.refresh(incident)

        assert incident.status == "PROCESSING"

    def test_incident_status_update_to_review(self, db_session):
        """Incident status can be updated to REVIEW after processing."""
        incident = Incident(
            src_user="a@b.com",
            dst_user="c@d.com",
            subject="Review Test",
            ip_address="1.2.3.4",
            status="PROCESSING",
        )
        db_session.add(incident)
        db_session.commit()

        incident.status = "REVIEW"
        incident.processed_at = datetime.now(UTC)
        db_session.commit()
        db_session.refresh(incident)

        assert incident.status == "REVIEW"
        assert incident.processed_at is not None

    def test_multiple_incidents_independent_status(self, db_session):
        """Multiple incidents should maintain independent lifecycle states."""
        inc1 = Incident(
            src_user="a@b.com", dst_user="c@d.com",
            subject="Inc 1", ip_address="1.1.1.1", status="PROCESSING",
        )
        inc2 = Incident(
            src_user="e@f.com", dst_user="g@h.com",
            subject="Inc 2", ip_address="2.2.2.2", status="REVIEW",
        )
        db_session.add_all([inc1, inc2])
        db_session.commit()

        assert inc1.status == "PROCESSING"
        assert inc2.status == "REVIEW"
