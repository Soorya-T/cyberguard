"""
A1 – OCSF Ingestion API Tests
==============================

Tests for:
- OCSF email event payload schema validation
- Async call to Pod B (/analyze)
- Verdict storage in database (Incident model)
- Ingestion endpoint (/api/v1/ingest)
"""

import uuid
from datetime import datetime, UTC
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.schemas.ocsf.email_event import EmailEvent
from app.models.incident import Incident
from app.services.pod_b_client import analyze_with_pod_b


# =============================================
# OCSF EmailEvent Schema Validation Tests
# =============================================


class TestEmailEventSchema:
    """Validate the OCSF EmailEvent Pydantic schema."""

    def test_valid_email_event(self):
        """A fully valid payload should parse without error."""
        event = EmailEvent(
            class_uid=4001,
            severity_id=3,
            time=datetime(2026, 2, 26, 12, 0, 0),
            src_user="alice@example.com",
            dst_user="bob@example.com",
            subject="Quarterly Report",
            ip_address="192.168.1.10",
        )
        assert event.class_uid == 4001
        assert event.severity_id == 3
        assert event.src_user == "alice@example.com"
        assert event.dst_user == "bob@example.com"
        assert event.subject == "Quarterly Report"
        assert event.ip_address == "192.168.1.10"

    def test_missing_class_uid_raises(self):
        """Omitting required field class_uid should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                severity_id=3,
                time=datetime.now(UTC),
                src_user="a@b.com",
                dst_user="c@d.com",
                subject="Test",
                ip_address="1.2.3.4",
            )

    def test_missing_severity_id_raises(self):
        """Omitting required field severity_id should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid=4001,
                time=datetime.now(UTC),
                src_user="a@b.com",
                dst_user="c@d.com",
                subject="Test",
                ip_address="1.2.3.4",
            )

    def test_missing_time_raises(self):
        """Omitting required field time should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid=4001,
                severity_id=3,
                src_user="a@b.com",
                dst_user="c@d.com",
                subject="Test",
                ip_address="1.2.3.4",
            )

    def test_missing_src_user_raises(self):
        """Omitting required field src_user should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid=4001,
                severity_id=3,
                time=datetime.now(UTC),
                dst_user="c@d.com",
                subject="Test",
                ip_address="1.2.3.4",
            )

    def test_missing_dst_user_raises(self):
        """Omitting required field dst_user should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid=4001,
                severity_id=3,
                time=datetime.now(UTC),
                src_user="a@b.com",
                subject="Test",
                ip_address="1.2.3.4",
            )

    def test_missing_subject_raises(self):
        """Omitting required field subject should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid=4001,
                severity_id=3,
                time=datetime.now(UTC),
                src_user="a@b.com",
                dst_user="c@d.com",
                ip_address="1.2.3.4",
            )

    def test_missing_ip_address_raises(self):
        """Omitting required field ip_address should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid=4001,
                severity_id=3,
                time=datetime.now(UTC),
                src_user="a@b.com",
                dst_user="c@d.com",
                subject="Test",
            )

    def test_invalid_class_uid_type_raises(self):
        """Non-integer class_uid should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid="not_an_int",
                severity_id=3,
                time=datetime.now(UTC),
                src_user="a@b.com",
                dst_user="c@d.com",
                subject="Test",
                ip_address="1.2.3.4",
            )

    def test_invalid_time_type_raises(self):
        """Non-datetime time should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent(
                class_uid=4001,
                severity_id=3,
                time="not-a-datetime",
                src_user="a@b.com",
                dst_user="c@d.com",
                subject="Test",
                ip_address="1.2.3.4",
            )

    def test_empty_payload_raises(self):
        """Completely empty payload should raise ValidationError."""
        with pytest.raises(PydanticValidationError):
            EmailEvent()

    def test_email_event_serialization(self):
        """EmailEvent.model_dump() should produce a serializable dict."""
        event = EmailEvent(
            class_uid=4001,
            severity_id=2,
            time=datetime(2026, 1, 1, 0, 0, 0),
            src_user="sender@corp.com",
            dst_user="receiver@corp.com",
            subject="Hello",
            ip_address="10.0.0.1",
        )
        data = event.model_dump()
        assert isinstance(data, dict)
        assert data["class_uid"] == 4001
        assert data["severity_id"] == 2
        assert data["src_user"] == "sender@corp.com"


# =============================================
# Pod B Async Client Tests
# =============================================


class TestPodBClient:
    """Test the async Pod B client (analyze_with_pod_b)."""

    @pytest.mark.asyncio
    async def test_analyze_with_pod_b_success(self):
        """Successful Pod B call should return parsed JSON response."""
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "risk_score": 85,
            "classification": "PHISHING",
            "explanation": "Suspicious sender domain",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.pod_b_client.httpx.AsyncClient", return_value=mock_client):
            result = await analyze_with_pod_b({
                "src_user": "attacker@evil.com",
                "dst_user": "victim@corp.com",
                "subject": "Urgent: Reset Password",
                "ip_address": "203.0.113.5",
            })

        assert result["risk_score"] == 85
        assert result["classification"] == "PHISHING"
        assert "explanation" in result

    @pytest.mark.asyncio
    async def test_analyze_with_pod_b_converts_datetime(self):
        """Datetime values in payload should be converted to ISO strings."""
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.json.return_value = {"risk_score": 50, "classification": "CLEAN"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        test_time = datetime(2026, 2, 26, 12, 0, 0)

        with patch("app.services.pod_b_client.httpx.AsyncClient", return_value=mock_client):
            await analyze_with_pod_b({
                "time": test_time,
                "src_user": "a@b.com",
            })

        # Verify the posted JSON had datetime converted to ISO string
        call_kwargs = mock_client.post.call_args
        sent_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert sent_json["time"] == test_time.isoformat()
        assert sent_json["src_user"] == "a@b.com"

    @pytest.mark.asyncio
    async def test_analyze_with_pod_b_raises_on_http_error(self):
        """Pod B returning an HTTP error should propagate via raise_for_status."""
        import httpx
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=httpx.Request("POST", "http://localhost:8001/analyze"),
            response=httpx.Response(500),
        )

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.pod_b_client.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                await analyze_with_pod_b({"src_user": "a@b.com"})


# =============================================
# Incident Model Tests
# =============================================


class TestIncidentModel:
    """Test the Incident ORM model."""

    def test_incident_creation(self, db_session):
        """Creating an Incident should persist all fields."""
        incident = Incident(
            src_user="alice@corp.com",
            dst_user="bob@corp.com",
            subject="Test Subject",
            ip_address="10.0.0.1",
            status="PROCESSING",
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)

        assert incident.id is not None
        assert incident.src_user == "alice@corp.com"
        assert incident.dst_user == "bob@corp.com"
        assert incident.subject == "Test Subject"
        assert incident.ip_address == "10.0.0.1"
        assert incident.status == "PROCESSING"

    def test_incident_default_status(self, db_session):
        """Default status should be RECEIVED."""
        incident = Incident(
            src_user="a@b.com",
            dst_user="c@d.com",
            subject="Default Status",
            ip_address="1.2.3.4",
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)

        assert incident.status == "RECEIVED"

    def test_incident_uuid_auto_generated(self, db_session):
        """Incident id should be auto-generated as a UUID string."""
        incident = Incident(
            src_user="a@b.com",
            dst_user="c@d.com",
            subject="UUID Test",
            ip_address="1.2.3.4",
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)

        # Should be a valid UUID string
        parsed = uuid.UUID(incident.id)
        assert str(parsed) == incident.id

    def test_incident_created_at_auto_set(self, db_session):
        """created_at should be automatically set on creation."""
        incident = Incident(
            src_user="a@b.com",
            dst_user="c@d.com",
            subject="Timestamp Test",
            ip_address="1.2.3.4",
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)

        assert incident.created_at is not None
        assert isinstance(incident.created_at, datetime)

    def test_incident_nullable_fields(self, db_session):
        """risk_score, classification, explanation, processed_at should be nullable."""
        incident = Incident(
            src_user="a@b.com",
            dst_user="c@d.com",
            subject="Nullable Test",
            ip_address="1.2.3.4",
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)

        assert incident.risk_score is None
        assert incident.classification is None
        assert incident.explanation is None
        assert incident.processed_at is None

    def test_incident_verdict_storage(self, db_session):
        """Storing Pod B verdict fields should persist correctly."""
        incident = Incident(
            src_user="a@b.com",
            dst_user="c@d.com",
            subject="Verdict Test",
            ip_address="1.2.3.4",
            status="PROCESSING",
        )
        db_session.add(incident)
        db_session.commit()

        # Simulate storing Pod B verdict
        incident.risk_score = 92
        incident.classification = "MALWARE"
        incident.explanation = "Known malware signature detected"
        incident.status = "REVIEW"
        incident.processed_at = datetime.now(UTC)
        db_session.commit()
        db_session.refresh(incident)

        assert incident.risk_score == 92
        assert incident.classification == "MALWARE"
        assert incident.explanation == "Known malware signature detected"
        assert incident.status == "REVIEW"
        assert incident.processed_at is not None


# =============================================
# Ingestion Endpoint Integration Tests
# =============================================


class TestIngestionEndpoint:
    """Integration tests for POST /api/v1/ingest."""

    VALID_PAYLOAD = {
        "class_uid": 4001,
        "severity_id": 3,
        "time": "2026-02-26T12:00:00",
        "src_user": "attacker@evil.com",
        "dst_user": "victim@corp.com",
        "subject": "Urgent: Reset Password",
        "ip_address": "203.0.113.5",
    }

    POD_B_VERDICT = {
        "risk_score": 85,
        "classification": "PHISHING",
        "explanation": "Suspicious sender domain",
    }

    @patch("app.routes.ingestion_routes.analyze_with_pod_b", new_callable=AsyncMock)
    def test_ingest_valid_event_returns_200(self, mock_pod_b, client, db_session):
        """Valid OCSF event should return 200 with incident_id and status."""
        mock_pod_b.return_value = self.POD_B_VERDICT

        response = client.post("/api/v1/ingest", json=self.VALID_PAYLOAD)

        assert response.status_code == 200
        data = response.json()
        assert "incident_id" in data
        assert data["status"] == "REVIEW"

    @patch("app.routes.ingestion_routes.analyze_with_pod_b", new_callable=AsyncMock)
    def test_ingest_stores_incident_in_db(self, mock_pod_b, client, db_session):
        """After ingestion, the incident should be persisted in the database."""
        mock_pod_b.return_value = self.POD_B_VERDICT

        response = client.post("/api/v1/ingest", json=self.VALID_PAYLOAD)
        incident_id = response.json()["incident_id"]

        incident = db_session.query(Incident).filter_by(id=incident_id).first()
        assert incident is not None
        assert incident.src_user == "attacker@evil.com"
        assert incident.dst_user == "victim@corp.com"
        assert incident.subject == "Urgent: Reset Password"
        assert incident.ip_address == "203.0.113.5"

    @patch("app.routes.ingestion_routes.analyze_with_pod_b", new_callable=AsyncMock)
    def test_ingest_stores_verdict_from_pod_b(self, mock_pod_b, client, db_session):
        """Pod B verdict (risk_score, classification, explanation) should be stored."""
        mock_pod_b.return_value = self.POD_B_VERDICT

        response = client.post("/api/v1/ingest", json=self.VALID_PAYLOAD)
        incident_id = response.json()["incident_id"]

        incident = db_session.query(Incident).filter_by(id=incident_id).first()
        assert incident.risk_score == 85
        assert incident.classification == "PHISHING"
        assert incident.explanation == "Suspicious sender domain"
        assert incident.status == "REVIEW"
        assert incident.processed_at is not None

    @patch("app.routes.ingestion_routes.analyze_with_pod_b", new_callable=AsyncMock)
    def test_ingest_calls_pod_b_with_event_data(self, mock_pod_b, client, db_session):
        """The ingestion endpoint should call Pod B with the event payload."""
        mock_pod_b.return_value = self.POD_B_VERDICT

        client.post("/api/v1/ingest", json=self.VALID_PAYLOAD)

        mock_pod_b.assert_called_once()
        call_args = mock_pod_b.call_args[0][0]
        assert call_args["src_user"] == "attacker@evil.com"
        assert call_args["dst_user"] == "victim@corp.com"

    def test_ingest_missing_required_field_returns_422(self, client, db_session):
        """Missing required fields should return 422 validation error."""
        incomplete_payload = {
            "class_uid": 4001,
            "severity_id": 3,
            # missing time, src_user, dst_user, subject, ip_address
        }
        response = client.post("/api/v1/ingest", json=incomplete_payload)
        assert response.status_code == 422

    def test_ingest_empty_payload_returns_422(self, client, db_session):
        """Empty JSON body should return 422."""
        response = client.post("/api/v1/ingest", json={})
        assert response.status_code == 422

    def test_ingest_invalid_time_format_returns_422(self, client, db_session):
        """Invalid time format should return 422."""
        payload = self.VALID_PAYLOAD.copy()
        payload["time"] = "not-a-datetime"
        response = client.post("/api/v1/ingest", json=payload)
        assert response.status_code == 422

    def test_ingest_invalid_class_uid_type_returns_422(self, client, db_session):
        """Non-numeric class_uid should return 422."""
        payload = self.VALID_PAYLOAD.copy()
        payload["class_uid"] = "invalid"
        response = client.post("/api/v1/ingest", json=payload)
        assert response.status_code == 422
