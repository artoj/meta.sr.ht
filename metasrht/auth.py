import bcrypt


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'),
            salt=bcrypt.gensalt()).decode('utf-8')


def check_password(password, hash):
    return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))
