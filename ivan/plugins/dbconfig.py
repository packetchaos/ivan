from .database import new_db_connection, create_table


def create_keys_table():
    database = r"ivan.db"
    key_conn = new_db_connection(database)
    key_table = """CREATE TABLE IF NOT EXISTS keys (
                            access_key text,
                            secret_key text,
                            hostname text,
                            port text
                            );"""
    create_table(key_conn, key_table)


def create_diff_table():
    database = r"ivan.db"
    diff_conn = new_db_connection(database)
    diff_table = """CREATE TABLE IF NOT EXISTS diff (
                        update_id integer PRIMARY KEY,
                        timestamp text,
                        days text,
                        update_type text,
                        exid text);"""
    create_table(diff_conn, diff_table)


def create_vulns_table():
    database = r"ivan.db"
    vuln_conn = new_db_connection(database)
    vuln_table = """CREATE TABLE IF NOT EXISTS vulns (
                            asset_ip text, 
                            asset_uuid text, 
                            asset_hostname text, 
                            first_found text, 
                            last_found text, 
                            output text, 
                            plugin_id text, 
                            plugin_name text, 
                            plugin_family text, 
                            port text, 
                            protocol text, 
                            severity text, 
                            repo_name text, 
                            repo_id text, 
                            uniqueness text, 
                            cves text,
                            score text,
                            exploit text,
                            xrefs text,
                            synopsis text, 
                            see_also text,
                            solution text,
                            version text, 
                            description text, 
                            cvss3_base_score text,
                            cvss3_temporal_score text,
                            cvss_base_score text,
                            cvss_temporal_score text,
                            OSes text,
                            url text
                            );"""
    vuln_conn.execute('pragma journal_mode=wal;')
    create_table(vuln_conn, vuln_table)


def create_scanid_table():
    database = r"ivan.db"
    scanid_conn = new_db_connection(database)
    scanid_table = """CREATE TABLE IF NOT EXISTS scanid (
                            asset_ip text, 
                            asset_uuid text, 
                            asset_hostname text, 
                            first_found text, 
                            last_found text, 
                            output text, 
                            plugin_id text, 
                            plugin_name text, 
                            plugin_family text, 
                            port text, 
                            protocol text, 
                            severity text, 
                            repo_name text, 
                            repo_id text, 
                            uniqueness text, 
                            cves text,
                            score text,
                            exploit text,
                            xrefs text,
                            synopsis text, 
                            see_also text,
                            solution text,
                            version text, 
                            description text, 
                            cvss3_base_score text,
                            cvss3_temporal_score text,
                            cvss_base_score text,
                            cvss_temporal_score text,
                            OSes text,
                            url text
                            );"""
    scanid_conn.execute('pragma journal_mode=wal;')
    create_table(scanid_conn, scanid_table)


def create_plugins_table():
    database = r"ivan.db"
    app_conn = new_db_connection(database)
    create_plugins = """CREATE TABLE IF NOT EXISTS plugins (
                            scan_uuid text,
                            name text,
                            cves text,
                            description text, 
                            family text, 
                            output text,
                            owasp text,
                            payload text,
                            plugin_id text,
                            plugin_mod_date text,
                            plugin_pub_date text,
                            proof text,
                            request_headers text,
                            response_headers text,
                            risk_factor text,
                            solution text,
                            url text,
                            xrefs text,
                            see_also text
                            );"""
    app_conn.execute('pragma journal_mode=wal;')

    create_table(app_conn, create_plugins)
