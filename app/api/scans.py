from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select, func
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional

from app.core.database import get_session
from app.models.scan import ScanRecord
from app.models.user import User
from app.api.auth import get_current_user
from app.services.scanner import scan_content

router = APIRouter(prefix="/api", tags=["scans"])

oauth2_optional = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


class ScanRequest(BaseModel):
    content: str
    scan_type: str  # 'URL', 'Email', or 'Message'


def _humanize(dt: datetime) -> str:
    """Convert a UTC datetime to a human-readable relative time string."""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = int((now - dt).total_seconds())
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def _badge_class(result: str) -> str:
    mapping = {
        "High Risk":   "score-high",
        "Medium Risk": "score-medium",
        "Low Risk":    "score-low",
        "Safe":        "score-safe",
    }
    return mapping.get(result, "score-safe")


# ── POST /api/scan ────────────────────────────────────────────────────────────
@router.post("/scan")
def perform_scan(
    payload: ScanRequest,
    session: Session = Depends(get_session),
    token: Optional[str] = Depends(oauth2_optional)
):
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty.")

    analysis = scan_content(payload.content, payload.scan_type)

    # Try to get current user (optional — extension works without login)
    current_user = None
    if token:
        try:
            import jwt
            from app.core.config import settings
            payload_data = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_id = payload_data.get("user_id")
            if user_id:
                current_user = session.get(User, user_id)
        except Exception:
            pass  # Invalid token — scan anyway, just don't save

    if current_user:
        record = ScanRecord(
            content=payload.content,
            scan_type=payload.scan_type,
            risk_score=analysis["risk_score"],
            result=analysis["result"],
            details=analysis["details"],
            user_id=current_user.id,
        )
        session.add(record)
        session.commit()
        session.refresh(record)

    return {
        "id": None if not current_user else record.id,
        "content": payload.content,
        "scan_type": payload.scan_type,
        "risk_score": analysis["risk_score"],
        "result":     analysis["result"],
        "details":    analysis["details"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "reasoning":  analysis.get("ai_reasoning", ""),
        "heuristic_flags": analysis.get("heuristic_flags", []),
        "breakdown":  analysis.get("breakdown", {}),
        "network":    analysis.get("network"),
        "engine":     analysis.get("engine", "heuristic")
    }


# ── GET /api/scans ────────────────────────────────────────────────────────────
@router.get("/scans")
def get_scan_history(limit: int = 100, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    scans = session.exec(
        select(ScanRecord)
        .where(ScanRecord.user_id == current_user.id)
        .order_by(ScanRecord.scanned_at.desc())
        .limit(limit)
    ).all()

    return [
        {
            "id":         s.id,
            "content":    s.content,
            "scan_type":  s.scan_type,
            "risk_score": s.risk_score,
            "result":     s.result,
            "details":    s.details,
            "scanned_at": _humanize(s.scanned_at),
        }
        for s in scans
    ]


# ── GET /api/dashboard/stats ──────────────────────────────────────────────────
@router.get("/dashboard/stats")
def get_dashboard_stats(session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    uid = current_user.id
    total      = session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid)).one() or 0
    high_risk  = session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid, ScanRecord.result == "High Risk")).one() or 0
    medium_risk= session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid, ScanRecord.result == "Medium Risk")).one() or 0
    low_risk   = session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid, ScanRecord.result == "Low Risk")).one() or 0
    safe       = session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid, ScanRecord.result == "Safe")).one() or 0

    urls       = session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid, ScanRecord.scan_type == "URL")).one() or 0
    emails     = session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid, ScanRecord.scan_type == "Email")).one() or 0
    messages   = session.exec(select(func.count(ScanRecord.id)).where(ScanRecord.user_id == uid, ScanRecord.scan_type == "Message")).one() or 0

    latest = session.exec(
        select(ScanRecord)
        .where(ScanRecord.user_id == uid)
        .order_by(ScanRecord.scanned_at.desc())
        .limit(1)
    ).first()

    recent_scans = session.exec(
        select(ScanRecord)
        .where(ScanRecord.user_id == uid)
        .order_by(ScanRecord.scanned_at.desc())
        .limit(5)
    ).all()

    recent_high = session.exec(
        select(ScanRecord)
        .where(ScanRecord.user_id == uid, ScanRecord.result == "High Risk")
        .order_by(ScanRecord.scanned_at.desc())
        .limit(5)
    ).all()

    def truncate(s, n=55):
        return s[:n] + "…" if len(s) > n else s

    return {
        "total":       total,
        "high_risk":   high_risk,
        "medium_risk": medium_risk,
        "low_risk":    low_risk,
        "safe":        safe,
        "type_breakdown": {
            "urls": urls,
            "emails": emails,
            "messages": messages
        },
        "latest_scan": {
            "risk_score": latest.risk_score,
            "result":     latest.result,
            "details":    latest.details,
            "content":    truncate(latest.content, 60),
            "scanned_at": _humanize(latest.scanned_at),
        } if latest else None,
        "recent_scans": [
            {
                "id":         s.id,
                "content":    truncate(s.content),
                "scan_type":  s.scan_type,
                "risk_score": s.risk_score,
                "result":     s.result,
                "scanned_at": _humanize(s.scanned_at),
            }
            for s in recent_scans
        ],
        "recent_high_risk": [
            {
                "id":        s.id,
                "content":   truncate(s.content, 60),
                "scan_type": s.scan_type,
                "result":    s.result,
                "scanned_at":_humanize(s.scanned_at),
            }
            for s in recent_high
        ],
    }
