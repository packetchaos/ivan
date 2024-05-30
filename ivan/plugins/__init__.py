from .update import update
from .keys import keys
from .find import find
from .ip import ip
from .display import display
from .export import export
from .scan import scan
from .smtp import smtp
from .ssh import ssh
from .mail import mail
from .software import software
from .push import push


def plugin_loader(group):
    group.add_command(update)
    group.add_command(keys)
    group.add_command(find)
    group.add_command(ip)
    group.add_command(display)
    group.add_command(export)
    group.add_command(scan)
    group.add_command(push)
    group.add_command(ssh)
    group.add_command(mail)
    group.add_command(smtp)
    group.add_command(software)
