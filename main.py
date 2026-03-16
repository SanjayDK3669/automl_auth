"""
main.py  —  AutoML.ai Auth Backend
Run:  uvicorn main:app --reload --port 8000
"""
import os
import hashlib
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import DuplicateKeyError

from database import users_col
from models import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    ResetSuccessResponse,
    SignupRequest,
    TokenResponse,
    UserResponse,
    UsernameCheckResponse,
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
    title="AutoML.ai Auth API",
    version="3.0.0",
    description="Auth service — signup, login, forgot password",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
_origins_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════════════════

def _serialize_user(doc: dict) -> dict:
    return {"id": str(doc["_id"]), "email": doc["email"], "username": doc["username"]}


# ═════════════════════════════════════════════════════════════════════════════
#  Health
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "AutoML.ai Auth API v3"}


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

    return TokenResponse(access_token=token, user=user_dict)


@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(body: LoginRequest):
    col  = users_col()
    user = col.find_one({"email": body.email.lower()})

    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(401, "Invalid email or password.")

    user_dict = _serialize_user(user)
    token     = create_access_token({"sub": user_dict["id"]}, timedelta(minutes=EXPIRE_MINUTES))

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
#  Forgot Password — 2-step flow (no email verification)
#  Step 1: POST /auth/forgot-password  { email }         → confirm email exists
#  Step 2: POST /auth/reset-password   { email, new_password } → update password
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/auth/forgot-password", response_model=MessageResponse, tags=["Forgot Password"])
def forgot_password(body: ForgotPasswordRequest):
    """
    Step 1 — Check the email exists in the database.
    Returns 200 if found so the frontend can proceed to the reset step.
    Returns 404 if the email is not registered.
    """
    email = body.email.lower()
    user  = users_col().find_one({"email": email})

    if not user:
        raise HTTPException(404, "No account found with that email address.")

    return MessageResponse(message="Email verified. Please set your new password.")


@app.post("/auth/reset-password", response_model=ResetSuccessResponse, tags=["Forgot Password"])
def reset_password(body: ResetPasswordRequest):
    """
    Step 2 — Update the user's password directly.
    Expects { email, new_password } in the request body.
    """
    email = body.email.lower()

    result = users_col().update_one(
        {"email": email},
        {"$set": {"password": hash_password(body.new_password)}},
    )

    if result.matched_count == 0:
        raise HTTPException(404, "User not found.")

    return ResetSuccessResponse(message="Password updated successfully. You can now sign in.")


# ═════════════════════════════════════════════════════════════════════════════
#  Run directly
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)