from datetime import datetime, timezone


def parse_iso_datetime(v):
    if isinstance(v, str):
        v = datetime.fromisoformat(v)

    if v.tzinfo is None or v.utcoffset() is None:
        v = v.replace(tzinfo=timezone.utc)

    return v


def to_iso(v):
    return parse_iso_datetime(v).isoformat(timespec='seconds')
