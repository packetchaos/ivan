import click
from .database import new_db_connection, db_query
import textwrap
from tenable.sc import TenableSC
import arrow
import datetime


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
                click.echo("{:60s} {:10s} {:30s} {}".format(str(scan['name']), str(scan['id']),
                                                            str(scan['status']),
                                                            str(scan['uuid'])))
            except KeyError:
                click.echo("{:60s} {:10s} {:30s} {}".format(str(scan['name']), str(scan['id']),
                                                            str(scan['status']),
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
            click.echo("{:34s} {:40s} {:40s} {:10s} {}".format(str(user["username"]), str(user["email"]),
                                                               str(user['uuid']), str(user['id']), str(user['locked'])))
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


@display.command(help="Display Scan Instances")
def instances():
    sc = tenb_connection()
    try:
        click.echo("\n{:60s} {:10s} {:15s} {:20s} {:20s} {}".format("Scan Name", "Scan ID", "Status",
                                                                    "Start Time", "Finish Time", "Assets Scanned"))
        click.echo("-" * 150)
        usable_list = []
        for scan in sc.scan_instances.list()['usable']:
            usable_list.append(scan['id'])

        for scanid in usable_list:
            scan = sc.scan_instances.details(id=scanid)
            start_time = arrow.get(float(scan['startTime']))
            finish_time = arrow.get(float(scan['finishTime']))

            try:
                click.echo("{:60s} {:10s} {:15s} {:20s} {:20s} {}".format(str(scan['name']), str(scan['id']),
                                                                          str(scan['status']),
                                                                          str(start_time.format('MM-DD-YYYY HH:mm:ss')),
                                                                          str(finish_time.format('MM-DD-YYYY HH:mm:ss')),
                                                                          str(scan['progress']['scannedSize'])))
            except KeyError:
                click.echo("{:60s} {:10s} {:30s} {}".format(str(scan['name']), str(scan['id']),
                                                            str(scan['status']), "No UUID"))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@display.command(help="Display Query IDs")
def query():
    sc = tenb_connection()
    try:
        click.echo("\n{:20s} {:45s} {}".format("Query ID", "Query Name", "Description"))
        click.echo("-" * 150)
        for qid in sc.queries.list()['usable']:
            click.echo("\n{:20s} {:45s} {}".format(qid['id'], qid['name'], qid['description']))
        click.echo()
    except KeyError:
        click.echo("Something went wrong")


@display.command(help="Display Static Asset Lists")
def static():
    import pprint
    sc = tenb_connection()
    click.echo("\n{:6} {:45} {:45}".format("ID", "Name", "Defined IPs"))
    click.echo("-" * 150)
    for alist in sc.asset_lists.list()['usable']:
        if alist['type'] == 'static':
            click.echo("{:6} {:45} {:45}".format(alist['id'], alist['name'],
                                                 str(sc.asset_lists.details(alist['id'])['typeFields']['definedIPs'])))

    click.echo("\n")