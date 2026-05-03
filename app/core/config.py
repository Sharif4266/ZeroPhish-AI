import os

class Settings:
    PROJECT_NAME: str = "ZeroPhish AI"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-for-dev")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./zerophish.db")
    
    # OAuth Settings
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    
    # Redirect URI Base (e.g., https://your-app.render.com)
    REDIRECT_URI_BASE: str = os.getenv("REDIRECT_URI_BASE", "http://localhost:8000")

settings = Settings()
