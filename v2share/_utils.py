"""v2share utilities"""

from typing import Dict, Sequence, Any
from urllib.parse import parse_qs, urlsplit


def filter_dict(d: Dict[Any, Any], values: Sequence[Any]) -> dict:
    """
    removes pairs with null value from dictionary
    :param d: the dictionary
    :param values: values you want to be filtered
    :return: the filtered dictionary
    """
    return dict(filter(lambda p: p[1] not in values, d.items()))


def set_path_early_data(path: str, early_data: int):
    parsed = urlsplit(path)
    query_params = parse_qs(parsed.query)

    query_params["ed"] = [str(early_data)]

    query_string = "&".join(
        "&".join([f"{key}={v}" for v in values]) for key, values in query_params.items()
    )

    return parsed.path + "?" + query_string
