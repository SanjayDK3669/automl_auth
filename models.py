"""
models.py  —  Pydantic request / response schemas
"""
import re
from pydantic import BaseModel, EmailStr, field_validator


# ── Auth ──────────────────────────────────────────────────────────────────────

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


# ── Forgot password ───────────────────────────────────────────────────────────

class ForgotPasswordRequest(BaseModel):
    """Step 1 — user submits their email."""
    email: EmailStr


class VerifyOTPRequest(BaseModel):
    """Step 2 — user submits the 6-digit OTP."""
    email: EmailStr
    otp:   str

    @field_validator("otp")
    @classmethod
    def otp_digits(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^\d{6}$", v):
            raise ValueError("OTP must be exactly 6 digits.")
        return v


class ResetPasswordRequest(BaseModel):
    """Step 3 — user submits new password using the reset token."""
    reset_token:      str
    password:         str
    confirm_password: str

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


# ── Responses ─────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         dict


class UserResponse(BaseModel):
    id:       str
    email:    str
    username: str


class MessageResponse(BaseModel):
    message: str


class UsernameCheckResponse(BaseModel):
    available: bool
    message:   str


class OTPSentResponse(BaseModel):
    message: str
    # We return a masked email so the frontend can display "Sent to j***@gmail.com"
    masked_email: str


class OTPVerifiedResponse(BaseModel):
    message:     str
    reset_token: str   # short-lived JWT to authorise the password reset


class ResetSuccessResponse(BaseModel):
    message: str
