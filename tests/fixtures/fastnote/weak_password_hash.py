import hashlib

def register_user(username, raw_password):
    # Vulnerable: MD5 used for password hashing (VG-AUTH-001)
    password_hash = hashlib.md5(raw_password.encode()).hexdigest()
    return {"user": username, "hash": password_hash}

def reset_password(user_id, new_pass):
    # Vulnerable: SHA1 used for password hashing (VG-AUTH-001)
    hashed_pwd = hashlib.sha1(new_pass.encode()).hexdigest()
    return hashed_pwd
