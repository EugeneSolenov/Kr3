import os

from dotenv import load_dotenv


load_dotenv()


MODE = os.getenv("MODE", "DEV").upper()
if MODE not in {"DEV", "PROD"}:
    raise ValueError("MODE must be DEV or PROD")

DOCS_USER = os.getenv("DOCS_USER", "valid_user")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "valid_password")

DATABASE_PATH = os.getenv("DATABASE_PATH", "app.db")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-secret-in-env")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
