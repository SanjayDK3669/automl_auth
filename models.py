"""
models.py  —  Pydantic request / response schemas
"""
from pydantic import BaseModel, EmailStr, field_validator
import re


# ── Request bodies ────────────────────────────────────────────────────────────

class SignupRequest(BaseModel):
    email:            EmailStr
    username:         str
    password:         str
    confirm_password: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters.")
        if len(v) > 30:
            raise ValueError("Username must be 30 characters or fewer.")
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username can only contain letters, numbers, and underscores.")
        return v

    @field_validator("password")
    @classmethod
    def password_strong(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match.")
        return v


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


# ── Response bodies ───────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         dict          # { id, email, username }


class UserResponse(BaseModel):
    id:       str
    email:    str
    username: str


class MessageResponse(BaseModel):
    message: str


class UsernameCheckResponse(BaseModel):
    available: bool
    message:   str
