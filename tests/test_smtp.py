import queue
import time
from email.headerregistry import Address
from email.message import EmailMessage

import pytest
from context import SMTP

test_message = """\
From: Alice <alice@example.org>\r
To: Bob <bob@example.org>\r
Subject: test for smtplibaio\r
\r
this is the email body :)"""


@pytest.mark.asyncio
async def test_smtp(smtp_controller):
    async with SMTP(
        hostname=smtp_controller.hostname, port=smtp_controller.port
    ) as client:
        await client.sendmail("alice@example.com", ["bob@example.com"], test_message)

    output = smtp_controller.handler.content.strip()

    assert output == test_message
