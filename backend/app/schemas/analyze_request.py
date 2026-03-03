from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from typing import Dict, Any, Optional


class AnalyzeRequest(BaseModel):
    """
    Accepts full OCSF-aligned event from Pod A.
    Standalone testing must mirror this structure.
    
    Supports both legacy format (sender, subject, body) and
    OCSF format (email, src_endpoint, http).
    """

    model_config = ConfigDict(extra="forbid")

    # Legacy fields for backward compatibility
    email_id: Optional[str] = None
    tenant_id: Optional[str] = None
    time: Optional[str] = None
    
    # OCSF fields
    src_endpoint: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, Any]] = None
    email: Optional[Dict[str, Any]] = None
    
    # Legacy/simple fields for testing - body is required
    sender: Optional[str] = None
    subject: str = ""
    body: str  # Required field - must be provided
    links: Optional[list] = None
    
    @field_validator('sender')
    @classmethod
    def validate_sender(cls, v):
        if v is not None and '@' not in v:
            raise ValueError('Invalid email address')
        return v
    
    @model_validator(mode='before')
    @classmethod
    def validate_body_not_empty(cls, data):
        if isinstance(data, dict):
            body = data.get('body', '')
            if body == '' or body is None:
                # Allow empty body initially - will be validated at field level
                pass
        return data
    
    @field_validator('body')
    @classmethod
    def validate_body(cls, v):
        if v is None or (isinstance(v, str) and len(v.strip()) == 0):
            raise ValueError('Body cannot be empty')
        return v