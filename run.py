import os
import urllib
import urllib2
import sys
import json
import time
import sqlite3
import mailer

from datetime import datetime

base_directory = os.path.dirname(os.path.realpath(__file__))

def fetch_json(url, params):
    data = urllib.urlencode(params)
    req = urllib2.Request(url, data)
    try:
        response = urllib2.urlopen(req)
        print("Http Status Code:" + str(response.getcode()))
        response_text = response.read()
        results = json.loads(response_text)
        return results
    except urllib2.HTTPError, e:
        print("Http Status Code:" + str(e.code))

def save_records(vulnerabilities):
    """
    Saves records that didn't existed, or needed updating. Returns the ones persisted.
    """
    con = sqlite3.connect("/home/anders/cvedetails/cve.db")
    cur = con.cursor()
    persisted = []
    for record in vulnerabilities:
        cur.execute("select * from record where cve_id = ? and update_date = ?", [record['cve_id'], record['update_date']])
        persisted_record = cur.fetchall()
        if persisted_record:
            #already persisted this record and update, skip and continue with the next.
            continue

        #insert new record and add to return list.
        con.execute("insert into record values (?,?,?,?,?,?,?,?,?,?)"
			,(None,record['cve_id'],record['cwe_id'],record['cvss_score'],record['exploit_count'],record['publish_date'],record['update_date'],record['summary'],record['url'], datetime.now()))
        con.commit()
        persisted.append(record)

    con.close()
    return persisted

def check_setup():
    con = sqlite3.connect(base_directory + "/cve.db")
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='record'")
    if not cur.fetchall():
        raise RuntimeError("app not setup. run `python setup.py` to setup application.")
    con.close()

if __name__ == '__main__':
    check_setup()
    json_conf = json.loads(open(base_directory + '/config.json').read())

    all_persisted = []
    for product, config in json_conf['products'].items():
        #add common options and fetch vulnerabilities
        params = dict(config.items() + json_conf['params'].items())
        vulnerabilities = fetch_json(json_conf['url'], params)
        persisted = save_records(vulnerabilities)
        #add product name to each vulnerability dictionary
        for p in persisted:
            p['product'] = product
        all_persisted.extend(persisted)
    mailer.send_mail(all_persisted)
