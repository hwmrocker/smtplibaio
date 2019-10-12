import queue
import socket
import threading
import time
from contextlib import closing
from subprocess import Popen, PIPE
import pytest


@pytest.fixture()
async def smtp_controller():
    import asyncio

    class ExampleHandler:
        async def handle_DATA(self, server, session, envelope):
            print("Message from %s" % envelope.mail_from)
            print("Message for %s" % envelope.rcpt_tos)
            print("Message data:\n")
            self.content = envelope.content.decode("utf8", errors="replace")
            print(self.content)
            print("End of message")
            return "250 Message accepted for delivery"

    from aiosmtpd.controller import Controller

    controller = Controller(ExampleHandler())
    controller.start()
    yield controller
    controller.stop()
