import click
from .sc_vuln_export import vuln_export


@click.group(help="Update the local Navi repository - saved in your current dir")
def update():
    pass


@update.command(help="Update the vulns Table")
def vulns():
    vuln_export()
