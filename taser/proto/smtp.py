import socket
import smtplib
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

def smtp_relay(from_addr, to_addr, subject, body, server, port, passwd=False, attachment=False,
               msg_type='html', reply_to=False, tls=False):

    # Attach Msg Components
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr

    if reply_to:
        msg['Reply-to'] = reply_to
    else:
        msg['Reply-to'] = from_addr

    msg['Subject'] = subject

    # Attach Body
    if msg_type in ['plain', 'txt']:
        msg.attach(MIMEText(body, 'plain'))
    else:
        msg.attach(MIMEText(body, 'html'))

    # Add attachment to msg
    if attachment:
        attach_file = open(attachment, "rb")
        p = MIMEBase('application', 'octet-stream')
        p.set_payload((attach_file).read())
        encoders.encode_base64(p)
        p.add_header('Content-Disposition', "attachment; filename= {}".format(attachment))
        msg.attach(p)

    #Send message
    socket.setdefaulttimeout(15)
    s = smtplib.SMTP(server, port)
    if tls:
        s.starttls()
    if passwd:
        s.login(from_addr, passwd)
    text = msg.as_string()

    # Send Mail and close
    s.sendmail(from_addr, to_addr, text)
    s.quit()
    return True