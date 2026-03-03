from pydantic import BaseModel, ConfigDict
from typing import Dict, Any


class AnalyzeRequest(BaseModel):
    """
    Accepts full OCSF-aligned event from Pod A.
    Standalone testing must mirror this structure.
    """

    model_config = ConfigDict(extra="allow")

    email_id: str
    tenant_id: str
    time: str
    src_endpoint: Dict[str, Any] | None = None
    http: Dict[str, Any] | None = None
    email: Dict[str, Any]