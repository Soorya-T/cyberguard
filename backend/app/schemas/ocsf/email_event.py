from pydantic import BaseModel
from datetime import datetime


class EmailEvent(BaseModel):
    class_uid: int
    severity_id: int
    time: datetime

    src_user: str
    dst_user: str
    subject: str
    ip_address: str