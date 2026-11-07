"""
User and Authentication Pydantic Models.
"""
from datetime import datetime
from typing import Optional
import uuid
from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="Analyst email address")
    password: str = Field(..., min_length=6, description="Password with minimum 6 characters")
    full_name: Optional[str] = "Security Analyst"
    organization: Optional[str] = "SOC / Cyber Threat Intelligence"
    recaptcha_token: Optional[str] = Field(None, description="Google reCAPTCHA v3 response token")


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., description="Password")
    recaptcha_token: Optional[str] = Field(None, description="Google reCAPTCHA v3 response token")


class UserResponse(BaseModel):
    user_id: str
    email: str
    full_name: str
    role: str = "analyst"
    organization: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

