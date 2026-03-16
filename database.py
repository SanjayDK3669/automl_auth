"""
database.py  —  PyMongo connection & collection helpers
"""
import os
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME   = os.getenv("DB_NAME",   "automl_auth")

# ── Singleton client ──────────────────────────────────────────────────────────
_client: MongoClient | None = None

def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        try:
            _client.admin.command("ping")
            print(f"✅ MongoDB connected  →  {MONGO_URI}  /  {DB_NAME}")
        except ConnectionFailure as e:
            print(f"❌ MongoDB connection failed: {e}")
            raise
    return _client


def get_db():
    return get_client()[DB_NAME]


# ── Users collection ──────────────────────────────────────────────────────────
def users_col():
    db  = get_db()
    col = db["users"]
    col.create_index([("email",    ASCENDING)], unique=True, name="unique_email")
    col.create_index([("username", ASCENDING)], unique=True, name="unique_username")
    return col


# ── OTP reset codes collection ────────────────────────────────────────────────
def otp_col():
    """
    Stores { email, otp_hash, created_at } documents.
    MongoDB TTL index auto-deletes documents 90 seconds after created_at,
    giving a small buffer beyond the 60-second frontend countdown.
    """
    db  = get_db()
    col = db["password_reset_otps"]
    # TTL index — MongoDB deletes docs 90s after the `created_at` field
    col.create_index(
        [("created_at", ASCENDING)],
        expireAfterSeconds=90,
        name="ttl_otp_cleanup",
    )
    # One OTP per email at a time
    col.create_index([("email", ASCENDING)], unique=True, name="unique_email_otp")
    return col


# ── Reset-token store (short-lived, after OTP verified) ───────────────────────
def reset_token_col():
    """
    Stores { reset_token_hash, email, created_at }.
    Auto-deleted after 300 seconds (5 minutes) — enough time to set a new password.
    """
    db  = get_db()
    col = db["password_reset_tokens"]
    col.create_index(
        [("created_at", ASCENDING)],
        expireAfterSeconds=300,
        name="ttl_reset_token_cleanup",
    )
    col.create_index([("email", ASCENDING)], unique=True, name="unique_email_token")
    return col
