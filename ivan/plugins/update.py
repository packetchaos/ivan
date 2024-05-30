import click
from .sc_vuln_export import vuln_export
from .epss import update_navi_with_epss


@click.group(help="Update the local Ivan repository - saved in your current dir")
def update():
    pass


@update.command(help="Update the vulns Table")
@click.option('--scan_id', default=None, help='Download only a specific scan')
def vulns(scan_id):
    vuln_export(scan_id=scan_id)
    

@update.command(help="Populate Navi DB with EPSS data")
@click.option('--day', '--d', required=True, help="Day of the Month; EX: 01 NOT 1")
@click.option('--month', '--m', required=True, help="Month of the year;EX: 04 NOT 4")
@click.option('--year', '--y', required=True, help="Year of your desire;EX: 2023 NOT 23")
def epss(day, month, year):
    update_navi_with_epss(day, month, year)
