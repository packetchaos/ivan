from .update import update
from .keys import keys
from .find import find
from .ip import ip
from .display import display
from .export import export


def plugin_loader(group):
    group.add_command(update)
    group.add_command(keys)
    group.add_command(find)
    group.add_command(ip)
    group.add_command(display)
    group.add_command(export)
