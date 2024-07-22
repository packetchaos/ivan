import click
from .sc_vuln_export import vuln_export
from .epss import update_navi_with_epss


@click.group(help="Update the local Ivan repository - saved in your current dir")
def update():
    pass


@update.command(help="Update the vulns Table")
@click.option('--scan_id', default=None, help='Download only a specific scan')
@click.option('--query_id', default=None, help='A T.sc Query ID to limit what is downloaded')
@click.option('--limit', default=200, help='Limit the pages in a response')
def vulns(scan_id, query_id, limit):
    vuln_export(scan_id=scan_id, query_id=query_id, limit=limit)
    

@update.command(help="Populate Navi DB with EPSS data")
@click.option('--day', '--d', required=True, help="Day of the Month; EX: 01 NOT 1")
@click.option('--month', '--m', required=True, help="Month of the year;EX: 04 NOT 4")
@click.option('--year', '--y', required=True, help="Year of your desire;EX: 2023 NOT 23")
def epss(day, month, year):
    update_navi_with_epss(day, month, year)
