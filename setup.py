import os
import sqlite3

current_directory = os.path.dirname(os.path.realpath(__file__))
con = sqlite3.connect("%s/cve.db" % current_directory)
cur = con.cursor()

create_tables = [
    """create table if not exists record (id integer primary key autoincrement,
			cve_id varchar(64),
			cwe_id integer,
			cvss_score float,
			exploit_count integer,
			publish_date TIMESTAMP,
			update_date TIMESTAMP,
			summary TEXT,
			url TEXT,
			updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)"""

]

for table_sql in create_tables:
    cur.execute(table_sql)

cur.close()
con.commit()
con.close()
