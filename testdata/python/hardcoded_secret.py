import os

# ❌ VULNERABLE: Hardcoded secret
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
SECRET_TOKEN = "secret-token-xyz"

# ✅ SAFE: Mengambil dari environment variable
DATABASE_URL = os.getenv("DATABASE_URL")
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")

# ❌ VULNERABLE: Juga terdeteksi
private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg..."