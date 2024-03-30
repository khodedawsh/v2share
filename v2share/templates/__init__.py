from datetime import datetime
from typing import Union

import jinja2

from v2share.templates.filters import CUSTOM_FILTERS

template_directories = ["templates"]

env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_directories))
env.filters.update(CUSTOM_FILTERS)
env.globals["now"] = datetime.utcnow


def render_template(template: str, context: Union[dict, None] = None) -> str:
    return env.get_template(template).render(context or {})
