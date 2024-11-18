import click
from .database import new_db_connection, db_query
import textwrap
from tenable.sc import TenableSC
import arrow
import datetime
import csv
from .display import display

@click.group()
def create():
    pass


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
            port = row[3]
            sc = TenableSC(hostname, port=port)
            # login to SC
            sc.login(access_key=access_key, secret_key=secret_key)

            return sc


@create.command(help="Create a Static IP")
@click.option("--ips", default='', help="Comma seperated list of ips within double quotes")
@click.option("--name", default='', help="Name of the static IP list")
@click.option("--description", default='', help="A description of your static IP list")
@click.option("--tag", default='', help="Tag for filtering your asset list")
@click.option("--file", default='', help="The full name of the CSV")
def static(ips, name, description, file, tag):
    sc = tenb_connection()

    if file:
        with open(file, 'r', newline='') as new_file:
            add_assets = csv.reader(new_file)

            for row in add_assets:

                name = row[0]
                ips = row[1]
                tag = row[2]
                description = row[3]

                try:
                    sc.asset_lists.create(name=name, list_type="static", tags=tag, description=description, ips=str(ips))
                except:
                    pass
        display.command(static)

    else:
        sc.asset_lists.create(name=name, list_type="static", tags=tag, description=description, ips=str(ips))
