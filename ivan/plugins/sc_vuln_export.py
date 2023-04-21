import time
import click
from tenable.sc import TenableSC
from sqlite3 import Error
from .database import new_db_connection, drop_tables, insert_vulns, db_query
from .dbconfig import create_vulns_table


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


def parse_data():
    sc = tenb_connection()
    database = r"ivan.db"
    vuln_conn = new_db_connection(database)
    vuln_conn.execute('pragma journal_mode=wal;')
    vuln_conn.execute('pragma cashe_size=-10000')
    vuln_conn.execute('pragma synchronous=OFF')
    with vuln_conn:
        try:

            # loop through all of the vulns in this chunk
            for vulns in sc.analysis.vulns(tool='vulndetails'):
                # create a blank list to append asset details
                vuln_list = []
                # Try block to ignore assets without IPs
                try:
                    try:
                        ipv4 = vulns['ip']
                        vuln_list.append(ipv4)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        asset_uuid = vulns['hostUUID']
                        vuln_list.append(asset_uuid)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        hostname = vulns['dnsName']
                        vuln_list.append(hostname)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        first_found = vulns['firstSeen']
                        vuln_list.append(first_found)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        last_found = vulns['lastSeen']
                        vuln_list.append(last_found)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        output = vulns['pluginText']
                        vuln_list.append(output)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        plugin_id = vulns['pluginID']
                        vuln_list.append(plugin_id)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        plugin_name = vulns['pluginName']
                        vuln_list.append(plugin_name)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        plugin_family = vulns['family']['name']
                        vuln_list.append(plugin_family)
                    except KeyError:
                        vuln_list.append(" ")
                    try:
                        port = vulns['port']
                        vuln_list.append(port)
                    except KeyError:
                        vuln_list.append(" ")
                    try:
                        protocol = vulns['protocol']
                        vuln_list.append(protocol)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        severity = vulns['severity']['name']
                        vuln_list.append(severity)
                    except KeyError:
                        vuln_list.append(" ")
                    try:
                        repo_name = vulns['repository']['name']
                        vuln_list.append(repo_name)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        repo_id = vulns['repository']['id']
                        vuln_list.append(repo_id)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        uniqueness = vulns['uniqueness']
                        vuln_list.append(uniqueness)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        cves = vulns['cve']
                        vuln_list.append(str(cves))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        score = vulns['vprScore']
                        vuln_list.append(score)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        exploit = vulns['exploitAvailable']
                        vuln_list.append(str(exploit))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        xrefs = vulns['xref']

                        vuln_list.append(str(xrefs))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        synopsis = vulns['synopsis']

                        vuln_list.append(str(synopsis))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        see_also = vulns['see_also']

                        vuln_list.append(str(see_also))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        solution = vulns['solution']

                        vuln_list.append(str(solution))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        version = vulns['version']

                        vuln_list.append(str(version))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        description = vulns['description']

                        vuln_list.append(str(description))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        cvss3_base_score = vulns['cvssV3BaseScore']

                        vuln_list.append(str(cvss3_base_score))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        cvss3_temporal_score = vulns['cvssV3TemporalScore']

                        vuln_list.append(str(cvss3_temporal_score))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        cvss_base_score = vulns['cvssBaseScore']

                        vuln_list.append(str(cvss_base_score))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        cvss_temporal_score = vulns['cvssTemporalScore']

                        vuln_list.append(str(cvss_temporal_score))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        OSes = vulns['operatingSystem']

                        vuln_list.append(str(OSes))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        insert_vulns(vuln_conn, vuln_list)
                    except Error as e:
                        click.echo(e)
                except IndexError:
                    click.echo("skipped one")
        except TypeError:
            click.echo("Your Export has no data.  It may have expired")

    vuln_conn.close()
    sc.logout()


def vuln_export():
    start = time.time()

    database = r"ivan.db"
    drop_conn = new_db_connection(database)
    drop_conn.execute('pragma journal_mode=wal;')

    # Right now we just drop the table.  Eventually I will actually update the database
    drop_tables(drop_conn, 'vulns')

    create_vulns_table()

    parse_data()

    click.echo("\nCreating a few indexes to make queries faster.\n")
    db_query("CREATE INDEX vulns_plugin_id on vulns (plugin_id);")
    db_query("CREATE INDEX vulns_ports on vulns (port);")
    db_query("CREATE INDEX vulns_cves on vulns (cves);")
    end = time.time()

    click.echo("Script took: {}".format(end-start))
