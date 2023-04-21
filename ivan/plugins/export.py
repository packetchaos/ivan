import click
from .query_export import query_export


@click.group(help="Export Tenable.io Data")
def export():
    pass


@export.command(help='Export data from the ivan.db to a csv')
@click.argument('statement')
@click.option('--file', default="query_data", help="Name of the file excluding 'csv'")
def query(statement, file):
    query_export(statement, file)


@export.command(help="Export All Vulnerability data in the Ivan Database to a CSV")
@click.option('--file', default="vuln_data", help="Name of the file excluding '.csv'")
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'info'], case_sensitive=False), multiple=True)
def vulns(file, severity):
    click.echo("\nExporting your data now. Saving {}.csv now...\n".format(file))

    if severity:

        if len(severity) == 1:
            # multiple choice values are returned as a tuple.
            # Here I break it out and put it in the format needed for sql
            asset_query = "select * from vulns where severity in ('{}');".format(severity[0])
        else:
            # Here I just send the tuple in the query
            asset_query = "select * from vulns where severity in {};".format(severity)
    else:
        asset_query = "select * from vulns;"

    query_export(asset_query, file)
