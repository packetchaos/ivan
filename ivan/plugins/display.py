import click
from .database import new_db_connection, db_query
import textwrap
from tenable.sc import TenableSC
import arrow

def compare_dates(given_date):
    today = arrow.now()
    try:
        given_date = arrow.get(given_date)
        days_difference = (today - given_date).days

        if days_difference > 35:
            return "no"
        else:
            return "yes"
    except ValueError:
        print("Invalid date format")


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


@click.group(help="Display information found in Tenable Security Center")
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


@display.command(help="Display Scans")
def scans():
    sc = tenb_connection()

    try:
        click.echo("\n{:60s} {:10s} {:30s} {}".format("Scan Name", "Scan ID", "Status", "UUID"))
        click.echo("-" * 150)

        for scan in sc.scans.list()['usable']:
            try:
                click.echo("{:60s} {:10s} {:30s} {}".format(str(scan['name']), str(scan['id']), str(scan['status']),
                                                            str(scan['uuid'])))
            except KeyError:
                click.echo("{:60s} {:10s} {:30s} {}".format(str(scan['name']), str(scan['id']), str(scan['status']),
                                                            "No UUID"))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@display.command(help="Display  all of the Users")
def users():
    sc = tenb_connection()

    try:
        click.echo("\n{:34s} {:40s} {:40s} {:10s} {}".format("User Name", "Login Email", "UUID", "ID", "Locked"))
        click.echo("-" * 150)
        for user in sc.users.list():
            click.echo("{:34s} {:40s} {:40s} {:10s} {}".format(str(user["username"]), str(user["email"]), str(user['uuid']), str(user['id']), str(user['locked'])))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@display.command(help="Display All Assets found in the last 30 days")
def assets():

    try:
        asset_list = []
        click.echo("\nBelow are the assets found in the last 30 days")
        click.echo("\n{:16} {:65} {:40}".format("IP Address", "FQDN", "UUID"))
        click.echo("-" * 150)
        asset_data = db_query("select asset_ip, asset_hostname, asset_uuid from vulns;")
        for asset in asset_data:
            if asset not in asset_list:
                asset_list.append(asset)

        for asset in asset_list:

            click.echo("{:16} {:65} {:40}".format(asset[0], asset[1], asset[2]))

        click.echo("\nTotal: {}\n\n".format(len(asset_list)))
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
