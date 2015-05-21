smtplibaio
==========

This is a port of the official python 3.4 smtplib, to make it compatible with asyncio. I converted only `SMTP` and `SMPT_SSL`.


Example

```Python
import asyncio
from libsmtpaio import SMTP_SSL

@asyncio.coroutine
def send(from_email, to_email, msg)
    server = SMTP_SSL()
    code, msg = yield from server.connect(mail_server)
    assert code == 220, "connect failed"
    try:
        yield from server.login(mailbox_name, mailbox_password)
        yield from server.sendmail(from_email, to_email, msg.as_string())
    finally:
        yield from server.quit()
```
