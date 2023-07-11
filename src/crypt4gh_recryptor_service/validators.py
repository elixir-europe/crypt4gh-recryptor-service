from datetime import datetime


def to_iso(v):
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    return v.isoformat(timespec='seconds')
