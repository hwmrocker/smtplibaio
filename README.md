smtplibaio
==========

This is a port of the official python 3.4 smtplib, to make it compatible with asyncio. I converted only `SMTP` and `SMPT_SSL`.


Example

```Python
import asyncio

from smtplibaio import SMTP_SSL

async def send(from_email, to_email, msg)
    server = SMTP_SSL()
    code, _ = await server.connect(mail_server)
    assert code == 220, "connect failed"
    try:
        await server.login(mailbox_name, mailbox_password)
        await server.sendmail(from_email, to_email, msg.as_string())
    finally:
        await server.quit()
```
