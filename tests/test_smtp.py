import queue
import time
from email.headerregistry import Address
from email.message import EmailMessage

import pytest

from smtplibaio import SMTP


def get_output(q):
    output = []
    while True:
        try:
            output.append(q.get(block=False))
        except queue.Empty:
            return ''.join(output)

        time.sleep(0.1)


@pytest.mark.asyncio
async def test_smtp(smtp_test_server):
    queue, port = smtp_test_server
    from_addr = Address("Alice", "alice", "example.org")
    to_addr = Address("Bob", "bob", "example.net")
    bcc_addr = Address("John", "john", "example.net")
    subject = "Testing smtplibaio"
    content = "Look, all emails sent from this method are BCCed to John !"
    recipients = [to_addr.addr_spec, bcc_addr.addr_spec]
    message = EmailMessage()
    message.add_header("From", str(from_addr))
    message.add_header("To", str(to_addr))
    message.add_header("Bcc", str(bcc_addr))
    message.add_header("Subject", subject)
    message.add_header("Content-type", "text/plain", charset="utf-8")
    message.set_content(content)
    async with SMTP(port=port) as client:
        await client.sendmail(from_addr.addr_spec, recipients, message.as_string())

    output = get_output(queue)
    expected = '\n'.join([
        '---------- MESSAGE FOLLOWS ----------',
        "b'From: Alice <alice@example.org>'",
        "b'To: Bob <bob@example.net>'",
        "b'Bcc: John <john@example.net>'",
        "b'Subject: Testing smtplibaio'",
        'b\'Content-Type: text/plain; charset="utf-8"\'',
        "b'Content-Transfer-Encoding: 7bit'",
        "b'MIME-Version: 1.0'",
        "b'X-Peer: 127.0.0.1'",
        "b''",
        "b'Look, all emails sent from this method are BCCed to John !'",
        '------------ END MESSAGE ------------'])

    assert output.strip().rstrip() == expected
