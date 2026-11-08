"""
Authentication Router.
Handles user registration, login with useremail and password, and profile retrieval.
"""
from datetime import datetime, timezone
import logging
import re
import uuid
import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status
from app.config import settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.database import get_db
from app.models.user import TokenResponse, UserLoginRequest, UserRegisterRequest, UserResponse

logger = logging.getLogger("vegaintel.auth")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


async def verify_recaptcha(token: str | None, action: str = "login"):
    """
    Validates Google reCAPTCHA v3 token against Google's verification API.
    Bypasses gracefully when RECAPTCHA_SECRET_KEY is not configured.
    """
    if not settings.RECAPTCHA_SECRET_KEY:
        return True

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA verification failed: token is required."
        )

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": settings.RECAPTCHA_SECRET_KEY,
                    "response": token
                }
            )
            if resp.status_code == 200:
                result = resp.json()
                if not result.get("success", False) or result.get("score", 1.0) < 0.4:
                    logger.warning(f"reCAPTCHA verification rejected. Result: {result}")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="reCAPTCHA verification rejected. Automated or high-risk activity detected."
                    )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"reCAPTCHA siteverify unreachable: {e}")
    return True


def get_current_user(
    authorization: str = Header(None),
    db=Depends(get_db)
) -> dict:
    """Dependency to retrieve and validate authenticated user from JWT Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ")[1]
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.users.find_one({"email": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@router.post("/register", response_model=TokenResponse)
async def register(req: UserRegisterRequest, db=Depends(get_db)):
    await verify_recaptcha(req.recaptcha_token, action="register")

    email_clean = req.email.lower().strip()

    # Check if user already exists (case-insensitive and trimmed)
    existing = db.users.find_one({
        "$or": [
            {"email": email_clean},
            {"email": {"$regex": f"^{re.escape(email_clean)}$", "$options": "i"}}
        ]
    })
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    user_doc = {
        "user_id": user_id,
        "email": email_clean,
        "password_hash": hash_password(req.password),
        "full_name": (req.full_name or "Security Analyst").strip(),
        "role": "analyst",
        "organization": (req.organization or "SOC / CTI Team").strip(),
        "created_at": now,
        "last_login": now
    }
    db.users.insert_one(user_doc)

    token = create_access_token({"sub": email_clean, "user_id": user_id, "role": "analyst"})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            user_id=user_id,
            email=email_clean,
            full_name=user_doc["full_name"],
            role="analyst",
            organization=user_doc["organization"],
            created_at=now,
            last_login=now
        )
    )


@router.post("/login", response_model=TokenResponse)
async def login(req: UserLoginRequest, db=Depends(get_db)):
    await verify_recaptcha(req.recaptcha_token, action="login")

    email_clean = req.email.lower().strip()
    user = db.users.find_one({
        "$or": [
            {"email": email_clean},
            {"email": req.email.strip()},
            {"email": {"$regex": f"^{re.escape(email_clean)}$", "$options": "i"}}
        ]
    })

    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password."
        )

    now = datetime.now(timezone.utc)
    db.users.update_one({"_id": user.get("_id")} if "_id" in user else {"email": user["email"]}, {"$set": {"last_login": now}})

    token = create_access_token({
        "sub": user["email"],
        "user_id": user.get("user_id"),
        "role": user.get("role", "analyst")
    })

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            full_name=user["full_name"],
            role=user.get("role", "analyst"),
            organization=user.get("organization"),
            created_at=user["created_at"],
            last_login=now
        )
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        user_id=current_user["user_id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        role=current_user.get("role", "analyst"),
        organization=current_user.get("organization"),
        created_at=current_user["created_at"],
        last_login=current_user.get("last_login")
    )

