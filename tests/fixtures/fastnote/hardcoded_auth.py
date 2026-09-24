# Hardcoded Bearer authentication token
ADMIN_BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"

def get_auth_header():
    return {"Authorization": ADMIN_BEARER_TOKEN}
