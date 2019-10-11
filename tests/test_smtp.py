import queue
import time
from email.headerregistry import Address
from email.message import EmailMessage

import pytest

from context import SMTP


@pytest.mark.asyncio
async def test_smtp(smtp_controller):
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
    async with SMTP(
        hostname=smtp_controller.hostname, port=smtp_controller.port
    ) as client:
        await client.sendmail(from_addr.addr_spec, recipients, message.as_string())

    output = smtp_controller.handler.content.strip().replace("\r\n", "\n")
    expected = """\
From: Alice <alice@example.org>
To: Bob <bob@example.net>
Bcc: John <john@example.net>
Subject: Testing smtplibaio
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit
MIME-Version: 1.0

Look, all emails sent from this method are BCCed to John !"""

    assert output == expected
