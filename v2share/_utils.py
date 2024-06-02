"""v2share utilities"""

from typing import Dict, Sequence, Any


def filter_dict(d: Dict[Any, Any], values: Sequence[Any]) -> dict:
    """
    removes pairs with null value from dictionary
    :param d: the dictionary
    :param values: values you want to be filtered
    :return: the filtered dictionary
    """
    return dict(filter(lambda p: p[1] not in values, d.items()))
