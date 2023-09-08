import click
from .scan_evaluation import evaluate_a_scan
from .sc_vuln_export import tenb_connection


@click.group(help="Start and Evaluate Scans")
def scan():
    pass


@scan.command()
def evaluate():
    evaluate_a_scan()


@scan.command(help="Start a valid Scan by Scan ID")
@click.argument('scan_id')
@click.option('--targets', default=None, help="Start the scan with alternative targets")
def start(scan_id, targets):
    tsc = tenb_connection()
    if targets is None:
        tsc.scans.launch(scan_id)
    else:
        tsc.scans.launch(scan_id, targets=targets)
