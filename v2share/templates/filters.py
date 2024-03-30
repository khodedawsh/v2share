import os
from datetime import datetime


def exclude_keys(obj, *target_keys):
    return {key: val for key, val in obj.items() if key not in target_keys}


def only_keys(obj, *target_keys):
    return {key: val for key, val in obj.items() if key in target_keys}


def datetimeformat(dt):
    if isinstance(dt, int):
        dt = datetime.fromtimestamp(dt)
    formatted_datetime = dt.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_datetime


def env_override(value, key):
    return os.getenv(key, value)


CUSTOM_FILTERS = {
    "except": exclude_keys,
    "only": only_keys,
    "datetime": datetimeformat,
}
