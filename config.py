import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "uba_staff_selection_secret_key")
    
    # Use PostgreSQL on production, SQLite locally
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        # For Vercel/Production - fix PostgreSQL URL scheme if needed
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = database_url
    else:
        # Local development
        SQLALCHEMY_DATABASE_URI = "sqlite:///staff.db"
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = "uploads/cv"
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    MAIL_ENABLED = os.getenv("MAIL_ENABLED", "false").lower() == "true"
    MAIL_HOST = os.getenv("MAIL_HOST", "")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USER = os.getenv("MAIL_USER", "")
    MAIL_PASS = os.getenv("MAIL_PASS", "")
    MAIL_FROM = os.getenv("MAIL_FROM", "")
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
