import click
from .scan_evaluation import evaluate_a_scan


@click.group(help="Create and Control Scans")
def scan():
    pass


@scan.command()
def evaluate():
    evaluate_a_scan()
