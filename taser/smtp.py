import socket
import smtplib
from os import path
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart


def smtp_relay(from_addr, to_addr, subject, body, server, port, passwd=False,
              attachment=False, msg_type='html', reply_to=False, tls=False, headers=None, timeout=15,
              raise_errors=False):
    headers = headers or {}
    # Addressing
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Reply-to'] = reply_to if reply_to else to_addr

    # Construct subject / body
    msg['Subject'] = subject
    subtype = 'plain' if msg_type in ['plain', 'txt'] else 'html'
    msg.attach(MIMEText(body, subtype))

    # Handle attachments
    if attachment:
        with open(attachment, "rb") as attach_file:
            p = MIMEBase('application', 'octet-stream')
            p.set_payload(attach_file.read())
            encoders.encode_base64(p)
            p.add_header('Content-Disposition', "attachment; filename= {}".format(path.basename(attachment)))
            for k, v in headers.items():
                p.add_header(k, v)
            msg.attach(p)

    # Define server & auth
    socket.setdefaulttimeout(timeout)
    try:
        with smtplib.SMTP(server, port) as smtp_client:
            if tls:
                smtp_client.starttls()
            if passwd:
                smtp_client.login(from_addr, passwd)
            smtp_client.sendmail(from_addr, to_addr, msg.as_string())
    except Exception:
        if raise_errors:
            raise
        return False
    return True
