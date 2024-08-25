""" Functions for database access """

import sqlite3
import os
import utils
from contextlib import contextmanager

schema="""
CREATE TABLE scan (id INTEGER primary key,
                   hash INTEGER,
                   src VARCHAR(16),
                   dst VARCHAR(16),
                   type VARCHAR(24),
                   ports TEXT,
                   timestamp REAL,
                   utc_timestamp VARCHAR(20));
"""

insert_sql="""
INSERT INTO scan (hash, src, dst, type, ports, timestamp, utc_timestamp)
values('{hash}', '{srcip}', '{dstip}', '{type}', '{ports_str}', {timestamp}, '{utc_timestamp}');
"""

@contextmanager
def cursor(conn):
    try:
        c=conn.cursor()
        yield c
    finally:
        c.close()
        conn.commit()
        
def create():
    """ Create database if does not exist """

    os.makedirs(os.path.expanduser('~/.config/pyscanlogd3/'), exist_ok=True)
    dbpath = os.path.join(os.path.expanduser('~/.config/pyscanlogd3/scan.db'))

    if not os.path.isfile(dbpath):
        print(f'creating scan db {dbpath} ...')
        with cursor(sqlite3.connect(dbpath)) as cur:
            try:
                cur.execute(schema)
                print('scan db created.')
            except Exception as ex:
                print(f'error creating scan table - {ex}')
    else:
        print(f'scan db {dbpath} already exists.')

    return dbpath
    
def insert(scan, dbpath):
    """ Insert scan into scan db """

    conn = sqlite3.connect(dbpath)

    def insert_row():
        with cursor(conn) as cur:
            srcip, dstip = utils.scan_ip2quad(scan)
            ports_str = ','.join([str(port) for port in sorted(scan.ports)])
            utc_timestamp = utils.timestamp_to_utc(scan.timestamp)
            context_dict = locals()
            context_dict.update(scan.__dict__)            
            sql = insert_sql.format(**context_dict)
            # print(sql)
            cur.execute(sql)

    return insert_row()
