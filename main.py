"""
main.py  —  AutoML.ai Auth Backend
Run with:  uvicorn main:app --reload --port 8000
"""
import os
from datetime import timedelta

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import DuplicateKeyError

from database import users_col
from models import (
    LoginRequest,
    MessageResponse,
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
    version="1.0.0",
    description="Authentication service — signup, login, token verification",
)

# ── CORS ──────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helper ────────────────────────────────────────────────────────────────────
def _serialize_user(doc: dict) -> dict:
    """Convert MongoDB doc to a safe JSON-serialisable dict."""
    return {
        "id":       str(doc["_id"]),
        "email":    doc["email"],
        "username": doc["username"],
    }


# ═════════════════════════════════════════════════════════════════════════════
# Routes
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "AutoML.ai Auth API"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}


# ── Username availability check ───────────────────────────────────────────────
@app.get(
    "/auth/check-username/{username}",
    response_model=UsernameCheckResponse,
    tags=["Auth"],
)
def check_username(username: str):
    """
    Returns { available: true/false }.
    Called live as the user types the username in the signup form.
    """
    col  = users_col()
    taken = col.find_one({"username": {"$regex": f"^{username}$", "$options": "i"}})
    if taken:
        return UsernameCheckResponse(available=False, message="Username is already taken.")
    return UsernameCheckResponse(available=True, message="Username is available!")


# ── Signup ────────────────────────────────────────────────────────────────────
@app.post(
    "/auth/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Auth"],
)
def signup(body: SignupRequest):
    col = users_col()

    # Check email uniqueness (extra safeguard beyond the DB index)
    if col.find_one({"email": body.email.lower()}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    # Check username uniqueness (case-insensitive)
    if col.find_one({"username": {"$regex": f"^{body.username}$", "$options": "i"}}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This username is already taken.",
        )

    # Insert new user
    new_user = {
        "email":    body.email.lower(),
        "username": body.username,
        "password": hash_password(body.password),
    }
    try:
        result   = col.insert_one(new_user)
        new_user["_id"] = result.inserted_id
    except DuplicateKeyError as e:
        # Race condition — someone grabbed the email/username a split second ago
        if "email" in str(e):
            raise HTTPException(status_code=409, detail="Email is already registered.")
        raise HTTPException(status_code=409, detail="Username is already taken.")

    user_dict  = _serialize_user(new_user)
    token      = create_access_token(
        {"sub": user_dict["id"]},
        expires_delta=timedelta(minutes=EXPIRE_MINUTES),
    )
    return TokenResponse(access_token=token, user=user_dict)


# ── Login ─────────────────────────────────────────────────────────────────────
@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(body: LoginRequest):
    col  = users_col()
    user = col.find_one({"email": body.email.lower()})

    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    user_dict = _serialize_user(user)
    token     = create_access_token(
        {"sub": user_dict["id"]},
        expires_delta=timedelta(minutes=EXPIRE_MINUTES),
    )
    return TokenResponse(access_token=token, user=user_dict)


# ── Get current user (token verification) ────────────────────────────────────
@app.get("/auth/me", response_model=UserResponse, tags=["Auth"])
def get_me(authorization: str = Header(...)):
    """
    Pass the JWT as:   Authorization: Bearer <token>
    Returns the user's profile if the token is valid.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header.")

    token   = authorization[len("Bearer "):]
    payload = decode_access_token(token)

    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    col  = users_col()
    try:
        user = col.find_one({"_id": ObjectId(payload["sub"])})
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token payload.")

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    return UserResponse(**_serialize_user(user))


# ── Run directly ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
