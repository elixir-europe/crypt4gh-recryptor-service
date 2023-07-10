from datetime import datetime


def to_iso(cls, v):
    if isinstance(v, str):
        v = datetime(v)
    return v.isoformat(timespec='minutes')
