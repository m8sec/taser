import socket
import smtplib
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart


def smtp_relay(from_addr, to_addr, subject, body, server, port, passwd=False,
              attachment=False, msg_type='html', reply_to=False, tls=False, headers={}):
    # Addressing
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Reply-to'] = reply_to if reply_to else to_addr

    # Construct subject / body
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html')) if msg_type in ['plain', 'txt'] else msg.attach(MIMEText(body, 'plain'))

    # Handle attachments
    if attachment:
        attach_file = open(attachment, "rb")
        p = MIMEBase('application', 'octet-stream')
        p.set_payload((attach_file).read())
        encoders.encode_base64(p)
        p.add_header('Content-Disposition', "attachment; filename= {}".format(attachment))
        for k, v in headers.items():
            p.add_header(k, v)
        msg.attach(p)

    # Define server & auth
    socket.setdefaulttimeout(15)
    s = smtplib.SMTP(server, port)
    if tls:
        s.starttls()
    if passwd:
        s.login(from_addr, passwd)
    text = msg.as_string()

    # Send
    s.sendmail(from_addr, to_addr, text)
    s.quit()
    return True
