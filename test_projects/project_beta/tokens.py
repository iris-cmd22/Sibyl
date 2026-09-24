import random
import string


def generate_token(length=16):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def session_id():
    return random.randint(100000, 999999)


def reset_code():
    return str(random.random())[2:8]
