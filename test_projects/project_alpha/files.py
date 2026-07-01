import os

BASE_DIR = "/var/app/notes"


def read_note(name):
    path = os.path.join(BASE_DIR, name)
    with open(path) as handle:
        return handle.read()
