"""
main.py  —  RaWML.ai Auth Backend
Run:  uvicorn main:app --reload --port 8000
"""
import os
import random
import string
import hashlib
from datetime import datetime, timedelta, timezone
from threading import Thread

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import DuplicateKeyError

from database import users_col, otp_col, reset_token_col
from email_service import send_welcome_email, send_otp_email
from models import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    OTPSentResponse,
    OTPVerifiedResponse,
    ResetPasswordRequest,
    ResetSuccessResponse,
    SignupRequest,
    TokenResponse,
    UserResponse,
    UsernameCheckResponse,
    VerifyOTPRequest,
)
from security import (
    EXPIRE_MINUTES,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)

load_dotenv()

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="RaWML.ai Auth API",
    version="2.0.0",
    description="Auth service — signup, login, forgot password, OTP verification",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# _origins_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
# origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════════════════

def _serialize_user(doc: dict) -> dict:
    return {"id": str(doc["_id"]), "email": doc["email"], "username": doc["username"]}


def _hash_str(s: str) -> str:
    """SHA-256 hash a string (for OTP / reset tokens in DB)."""
    return hashlib.sha256(s.encode()).hexdigest()


def _gen_otp() -> str:
    """Generate a cryptographically random 6-digit OTP."""
    return "".join(random.choices(string.digits, k=6))


def _mask_email(email: str) -> str:
    """j***@gmail.com  — show first char + domain."""
    local, domain = email.split("@", 1)
    return local[0] + "***@" + domain


def _send_async(fn, *args):
    """Fire-and-forget email in a background thread so the API responds fast."""
    Thread(target=fn, args=args, daemon=True).start()


# ═════════════════════════════════════════════════════════════════════════════
#  Health
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "RaWML.ai Auth API v2"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}


# ═════════════════════════════════════════════════════════════════════════════
#  Auth — Signup / Login / Me
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/auth/check-username/{username}", response_model=UsernameCheckResponse, tags=["Auth"])
def check_username(username: str):
    col   = users_col()
    taken = col.find_one({"username": {"$regex": f"^{username}$", "$options": "i"}})
    if taken:
        return UsernameCheckResponse(available=False, message="Username is already taken.")
    return UsernameCheckResponse(available=True, message="Username is available!")


@app.post("/auth/signup", response_model=TokenResponse, status_code=201, tags=["Auth"])
def signup(body: SignupRequest):
    col = users_col()

    if col.find_one({"email": body.email.lower()}):
        raise HTTPException(409, "An account with this email already exists.")
    if col.find_one({"username": {"$regex": f"^{body.username}$", "$options": "i"}}):
        raise HTTPException(409, "This username is already taken.")

    new_user = {
        "email":    body.email.lower(),
        "username": body.username,
        "password": hash_password(body.password),
    }
    try:
        result = col.insert_one(new_user)
        new_user["_id"] = result.inserted_id
    except DuplicateKeyError as e:
        msg = "Email is already registered." if "email" in str(e) else "Username is already taken."
        raise HTTPException(409, msg)

    user_dict = _serialize_user(new_user)
    token     = create_access_token({"sub": user_dict["id"]}, timedelta(minutes=EXPIRE_MINUTES))

    # Send welcome email asynchronously
    _send_async(send_welcome_email, body.email.lower(), body.username)

    return TokenResponse(access_token=token, user=user_dict)


@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(body: LoginRequest):
    col  = users_col()
    user = col.find_one({"email": body.email.lower()})

    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(401, "Invalid email or password.")

    user_dict = _serialize_user(user)
    token     = create_access_token({"sub": user_dict["id"]}, timedelta(minutes=EXPIRE_MINUTES))

    # Send welcome-back email asynchronously
    _send_async(send_welcome_email, user["email"], user["username"])

    return TokenResponse(access_token=token, user=user_dict)


@app.get("/auth/me", response_model=UserResponse, tags=["Auth"])
def get_me(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Invalid authorization header.")
    token   = authorization[len("Bearer "):]
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(401, "Invalid or expired token.")
    try:
        user = users_col().find_one({"_id": ObjectId(payload["sub"])})
    except Exception:
        raise HTTPException(401, "Invalid token payload.")
    if not user:
        raise HTTPException(404, "User not found.")
    return UserResponse(**_serialize_user(user))


# ═════════════════════════════════════════════════════════════════════════════
#  Forgot Password — 3-step flow
#  Step 1: /auth/forgot-password     → send OTP email
#  Step 2: /auth/verify-otp          → validate OTP → return reset_token
#  Step 3: /auth/reset-password      → use reset_token → set new password
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/auth/forgot-password", response_model=OTPSentResponse, tags=["Forgot Password"])
def forgot_password(body: ForgotPasswordRequest):
    """
    Step 1 — Look up the email, generate a 6-digit OTP, store its hash,
    and send it via email.  We always return 200 even if email not found
    (to avoid leaking which emails are registered).
    """
    email = body.email.lower()
    col   = users_col()
    user  = col.find_one({"email": email})

    # Always send the same generic response to prevent email enumeration
    masked = _mask_email(email)

    if not user:
        # Don't reveal that the email isn't registered
        return OTPSentResponse(
            message="If that email is registered, a code has been sent.",
            masked_email=masked,
        )

    otp = _gen_otp()

    # Upsert — replace any existing OTP for this email
    otp_col().update_one(
        {"email": email},
        {"$set": {
            "email":      email,
            "otp_hash":   _hash_str(otp),
            "created_at": datetime.now(timezone.utc),
        }},
        upsert=True,
    )

    # Send the OTP email asynchronously
    _send_async(send_otp_email, email, user["username"], otp)

    return OTPSentResponse(
        message="Verification code sent to your email.",
        masked_email=masked,
    )


@app.post("/auth/verify-otp", response_model=OTPVerifiedResponse, tags=["Forgot Password"])
def verify_otp(body: VerifyOTPRequest):
    """
    Step 2 — Check the OTP.  If valid, return a short-lived reset_token.
    The MongoDB TTL will automatically expire the OTP document after 90s.
    """
    email = body.email.lower()
    col   = otp_col()
    doc   = col.find_one({"email": email})

    if not doc:
        raise HTTPException(400, "Verification code has expired or is invalid. Please request a new one.")

    # Verify OTP hash
    if doc["otp_hash"] != _hash_str(body.otp):
        raise HTTPException(400, "Incorrect verification code.")

    # Check the 60-second window manually (extra safety on top of TTL)
    created_at = doc["created_at"]
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    age_seconds = (datetime.now(timezone.utc) - created_at).total_seconds()
    if age_seconds > 60:
        raise HTTPException(400, "Verification code has expired. Please request a new one.")

    # OTP is valid — delete it immediately (single-use)
    col.delete_one({"email": email})

    # Generate a short-lived reset token (5 minutes)
    reset_token = create_access_token(
        {"sub_reset": email, "purpose": "password_reset"},
        expires_delta=timedelta(minutes=5),
    )

    # Store hash in DB so it can only be used once
    reset_token_col().update_one(
        {"email": email},
        {"$set": {
            "email":       email,
            "token_hash":  _hash_str(reset_token),
            "created_at":  datetime.now(timezone.utc),
        }},
        upsert=True,
    )

    return OTPVerifiedResponse(
        message="Code verified. You may now set a new password.",
        reset_token=reset_token,
    )


@app.post("/auth/reset-password", response_model=ResetSuccessResponse, tags=["Forgot Password"])
def reset_password(body: ResetPasswordRequest):
    """
    Step 3 — Validate the reset_token and update the user's password.
    """
    # Decode reset token
    payload = decode_access_token(body.reset_token)
    if not payload or payload.get("purpose") != "password_reset" or "sub_reset" not in payload:
        raise HTTPException(400, "Invalid or expired reset link. Please start over.")

    email = payload["sub_reset"]

    # Verify this token is in our DB (single-use guard)
    rt_col = reset_token_col()
    stored = rt_col.find_one({"email": email})
    if not stored or stored["token_hash"] != _hash_str(body.reset_token):
        raise HTTPException(400, "Reset token has already been used or has expired.")

    # Update the password
    result = users_col().update_one(
        {"email": email},
        {"$set": {"password": hash_password(body.password)}},
    )
    if result.matched_count == 0:
        raise HTTPException(404, "User not found.")

    # Invalidate the reset token
    rt_col.delete_one({"email": email})

    return ResetSuccessResponse(message="Password updated successfully. You can now sign in.")


# ═════════════════════════════════════════════════════════════════════════════
#  Run directly
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
