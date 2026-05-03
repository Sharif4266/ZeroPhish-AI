from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select
from pydantic import BaseModel
import jwt
import httpx
import urllib.parse

from app.core.config import settings
from app.core.database import get_session
from app.models.user import User
from app.core.security import get_password_hash, verify_password, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# --- OAuth Endpoints ---

@router.get("/google/login")
def google_login():
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": f"{settings.REDIRECT_URI_BASE}/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account"
    }
    url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

@router.get("/google/callback")
async def google_callback(code: str, session: Session = Depends(get_session)):
    async with httpx.AsyncClient() as client:
        # 1. Exchange code for token
        token_res = await client.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": f"{settings.REDIRECT_URI_BASE}/auth/google/callback",
            "grant_type": "authorization_code"
        })
        token_data = token_res.json()
        if "access_token" not in token_data:
            raise HTTPException(status_code=400, detail="Failed to get Google access token")

        # 2. Get user info
        user_res = await client.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={
            "Authorization": f"Bearer {token_data['access_token']}"
        })
        user_info = user_res.json()
        email = user_info.get("email")
        full_name = user_info.get("name", "")

        # 3. Login or Register
        user = session.exec(select(User).where(User.email == email.lower())).first()
        if not user:
            user = User(
                email=email.lower(),
                full_name=full_name,
                hashed_password="OAUTH_USER" # Mark as OAuth user
            )
            session.add(user)
            session.commit()
            session.refresh(user)

        token = create_access_token({"sub": user.email, "user_id": user.id})
        # Redirect to frontend with token (or handle via frontend JS)
        return RedirectResponse(url=f"/dashboard?token={token}")

@router.get("/github/login")
def github_login():
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": f"{settings.REDIRECT_URI_BASE}/auth/github/callback",
        "scope": "user:email"
    }
    url = f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

@router.get("/github/callback")
async def github_callback(code: str, session: Session = Depends(get_session)):
    async with httpx.AsyncClient() as client:
        # 1. Exchange code for token
        token_res = await client.post("https://github.com/login/oauth/access_token", 
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{settings.REDIRECT_URI_BASE}/auth/github/callback"
            }
        )
        token_data = token_res.json()
        if "access_token" not in token_data:
            raise HTTPException(status_code=400, detail="Failed to get GitHub access token")

        # 2. Get user info
        user_res = await client.get("https://api.github.com/user", headers={
            "Authorization": f"Bearer {token_data['access_token']}"
        })
        user_info = user_res.json()
        
        # GitHub emails might be private, need to fetch specifically
        email_res = await client.get("https://api.github.com/user/emails", headers={
            "Authorization": f"Bearer {token_data['access_token']}"
        })
        emails = email_res.json()
        primary_email = next((e["email"] for e in emails if e["primary"]), emails[0]["email"])
        full_name = user_info.get("name") or user_info.get("login")

        # 3. Login or Register
        user = session.exec(select(User).where(User.email == primary_email.lower())).first()
        if not user:
            user = User(
                email=primary_email.lower(),
                full_name=full_name,
                hashed_password="OAUTH_USER"
            )
            session.add(user)
            session.commit()
            session.refresh(user)

        token = create_access_token({"sub": user.email, "user_id": user.id})
        return RedirectResponse(url=f"/dashboard?token={token}")

# --- Legacy Endpoints ---

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = session.get(User, user_id)
    if user is None:
        raise credentials_exception
    return user


class RegisterRequest(BaseModel):
    full_name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/register")
def register(payload: RegisterRequest, session: Session = Depends(get_session)):
    if not payload.full_name.strip():
        raise HTTPException(status_code=400, detail="Full name is required.")
    if not payload.email.strip() or "@" not in payload.email:
        raise HTTPException(status_code=400, detail="A valid email address is required.")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    existing = session.exec(select(User).where(User.email == payload.email.lower())).first()
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name.strip(),
        hashed_password=get_password_hash(payload.password),
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    token = create_access_token({"sub": user.email, "user_id": user.id})
    return {
        "message": "Account created successfully.",
        "access_token": token,
        "user": {"id": user.id, "email": user.email, "full_name": user.full_name},
    }


@router.post("/login")
def login(payload: LoginRequest, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == payload.email.lower())).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_access_token({"sub": user.email, "user_id": user.id})
    return {
        "access_token": token,
        "user": {"id": user.id, "email": user.email, "full_name": user.full_name},
    }

@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name
    }
