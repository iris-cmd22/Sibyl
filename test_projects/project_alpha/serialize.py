import base64
import pickle


def load_prefs(blob):
    raw = base64.b64decode(blob)
    return pickle.loads(raw)
