import queue
import socket
import threading
import time
from contextlib import closing
from subprocess import Popen, PIPE
import pytest


@pytest.fixture()
def unused_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def reader(p, q):
    while True:
        q.put(p.stdout.readline().decode('utf-8'))


@pytest.fixture()
def smtp_test_server(unused_port):
    p = Popen(['python', '-m', 'smtpd', '-c', 'DebuggingServer', '-n', f'127.0.0.1:{str(unused_port)}'], stdout=PIPE)
    time.sleep(1)
    q = queue.Queue()
    t = threading.Thread(target=reader, args=(p, q), daemon=True)
    t.start()
    try:
        yield q, unused_port
    finally:
        p.terminate()
