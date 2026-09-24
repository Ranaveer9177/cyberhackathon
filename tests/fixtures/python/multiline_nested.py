def outer_service(user_id):
    def inner_db_lookup(id_param):
        stmt = "SELECT id, username, email FROM accounts WHERE id = '" + \
            id_param + "'"
        return db.execute(stmt)

    return inner_db_lookup(user_id)
