from .database import new_db_connection
from tenable.sc import TenableSC


def ivan_version():
    return "ivan-0.0.1"


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
            #sc.login(access_key=access_key, secret_key=secret_key)

            return sc, access_key, secret_key
