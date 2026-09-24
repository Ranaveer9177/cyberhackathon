def get_user_profile(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    db.execute(query)
