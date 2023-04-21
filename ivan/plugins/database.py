import sqlite3
from sqlite3 import Error
import click


def new_db_connection(db_file):
    # create a connection to our database
    conn = None
    try:
        # A database file will be created if one doesn't exist
        conn = sqlite3.connect(db_file, timeout=10.0)
    except Error as E:
        click.echo(E)
    return conn


def create_table(conn, table_information):
    try:
        c = conn.cursor()
        c.execute('pragma journal_mode=wal;')
        c.execute(table_information)
    except Error as e:
        click.echo(e)


def db_query(statement):
    # start = time.time()
    database = r"ivan.db"
    query_conn = new_db_connection(database)
    with query_conn:
        cur = query_conn.cursor()
        cur.execute('pragma journal_mode=wal;')
        cur.execute('pragma cache_size=-10000;')
        cur.execute('PRAGMA synchronous = OFF')
        cur.execute('pragma threads=4')
        cur.execute(statement)

        data = cur.fetchall()
        # end = time.time()
        # total = end - start
    query_conn.close()
    # click.echo("Sql Query took: {} seconds".format(total))
    return data


def insert_assets(conn, assets):
    sql = '''INSERT or IGNORE into assets(
                                          ip_address, 
                                          hostname, 
                                          fqdn, 
                                          uuid, 
                                          first_found, 
                                          last_found, 
                                          operating_system,
                                          mac_address, 
                                          agent_uuid, 
                                          last_licensed_scan_date, 
                                          network, 
                                          acr, 
                                          aes, 
                                          aws_id,
                                          aws_ec2_instance_state,
                                          aws_ec2_name,
                                          aws_ec2_region,
                                          aws_availability_zone,
                                          gcp_instance_id,
                                          gcp_project_id,
                                          gcp_zone,
                                          url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, assets)


def drop_tables(conn, table):
    try:
        drop_table = '''DROP TABLE {}'''.format(table)
        cur = conn.cursor()
        cur.execute('pragma journal_mode=wal;')
        cur.execute(drop_table)
    except Error:
        pass


def insert_vulns(conn, vulns):
    sql = '''INSERT or IGNORE into vulns(
                            asset_ip, 
                            asset_uuid, 
                            asset_hostname, 
                            first_found, 
                            last_found, 
                            output, 
                            plugin_id, 
                            plugin_name, 
                            plugin_family, 
                            port, 
                            protocol, 
                            severity,
                            repo_name,
                            repo_id,
                            uniqueness,
                            cves,
                            score,
                            exploit,
                            xrefs,
                            synopsis, 
                            see_also,
                            solution,
                            version, 
                            description, 
                            cvss3_base_score,
                            cvss3_temporal_score,
                            cvss_base_score,
                            cvss_temporal_score,
                            OSes
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''

    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, vulns)

