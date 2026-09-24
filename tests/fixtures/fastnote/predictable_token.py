import base64
import time

def generate_password_reset_token(email):
    # Vulnerable: predictable token based on base64 encoding of email (VG-AUTH-002)
    token = base64.b64encode(email.encode()).decode()
    return token

def create_session_token(user_id):
    # Vulnerable: predictable token from user_id + timestamp (VG-AUTH-002)
    reset_token = f"{user_id}_{int(time.time())}"
    return reset_token
