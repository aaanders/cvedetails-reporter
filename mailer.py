import os
import json
import smtplib

from datetime import date
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_mail(records):
    conf = json.load(open(os.path.dirname(os.path.realpath(__file__)) + '/mail_config.json', 'r'))

    me = conf['from_address']
    you = conf['to_addresses'] #list of strings/email
    host = conf['host']
    port = conf['port']
    passwd = conf['password']

    msg = MIMEMultipart('alternative')
    msg['Subject'] = "CVEDetails %s" % date.today()
    msg['From'] = me
    msg['To'] = "; ".join(you)

    body = build_body(records)
    part = MIMEText(body, 'html')
    msg.attach(part)

    session = smtplib.SMTP(host, port)
    session.starttls()
    session.login(me, passwd)
    session.sendmail(me, you, msg.as_string())
    session.quit()

def build_body(records):
    if not records:
        return "<html><body>Nothing to report.</body></html>"
    table_rows = []
    table_rows.append("<html><head></head><body><style type='text/css'>text-align:center;}</style><table border='1'>")
    table_rows.append("<thead><tr><th>product</th><th>cve_id</th><th>cvss_score</th><th>cwe_id</th><th>exploit_count</th><th>publish_date</th><th>update_date</th><th>summary</th><th>url</th></tr></thead>")

    table_rows.append("<tbody>")
    row = "<tr><td>%(product)s</td><td>%(cve_id)s</td><td>%(cvss_score)s</td><td>%(cwe_id)s</td><td>%(exploit_count)s</td><td>%(publish_date)s</td><td>%(update_date)s</td><td>%(summary)s</td><td><a href='%(url)s'>%(url)s</a></td></tr>"
    table_rows.extend([row % record for record in records])
    table_rows.append("</tbody></table></body></html>")

    return "".join(table_rows)
