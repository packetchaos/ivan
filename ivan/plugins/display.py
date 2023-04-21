import click
from .database import new_db_connection, db_query
import textwrap
from tenable.sc import TenableSC


def tenb_connection():
    database = r"ivan.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT * from keys;")
        rows = cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]
            hostname = row[2]
            sc = TenableSC(hostname)
            # login to SC
            sc.login(access_key=access_key, secret_key=secret_key)

            return sc


@click.group(help="Display information found in Tenable.io")
def display():
    pass


@display.command(help="Display all repos")
def repo():
    sc = tenb_connection()
    try:
        click.echo("\n{:35s} {:20}".format("Repo Name", "Repo ID"))
        click.echo("-" * 150)
        for nessus in sc.repositories.list():
            click.echo("{:35s} {:20}".format(str(nessus["name"]), str(nessus["id"])))
        click.echo()
        sc.logout()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
