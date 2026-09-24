def get_user_profile(user_input):
    query = "SELECT * FROM users WHERE username = ?"
    db.execute(query, (user_input,))
