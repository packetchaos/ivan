import click
from .sc_vuln_export import vuln_export


@click.group(help="Update the local Ivan repository - saved in your current dir")
def update():
    pass


@update.command(help="Update the vulns Table")
@click.option('--scan_id', default=None, help='Download only a specific scan')
def vulns(scan_id):
    vuln_export(scan_id=scan_id)
