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


def insert_scanid(conn, scanid):
    sql = '''INSERT or IGNORE into scanid(
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
    cur.execute(sql, scanid)


def insert_software(conn, software):
    sql = '''INSERT or IGNORE into software(software_string, asset_uuid) VALUES(?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, software)


def update_software(conn, software, asset_list):
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute('UPDATE software SET asset_uuid=? WHERE software_string=?', (str()))


def insert_epss(conn2, epss_data):
    sql_epss = '''INSERT or IGNORE into epss(
                            cve,
                            epss_value,
                            percentile) VALUES(?,?,?)'''
    epss_cur = conn2.cursor()
    epss_cur.execute('pragma journal_mode=wal;')
    epss_cur.execute(sql_epss, epss_data)
