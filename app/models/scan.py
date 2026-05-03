from typing import Optional
from sqlmodel import Field, SQLModel
from datetime import datetime

class ScanRecordBase(SQLModel):
    content: str
    scan_type: str = Field(description="URL, Email, or Message")
    risk_score: int
    result: str = Field(description="Safe, Suspicious, or High Risk")
    details: Optional[str] = None
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")

class ScanRecord(ScanRecordBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)

class ScanRecordRead(ScanRecordBase):
    id: int
    scanned_at: datetime
