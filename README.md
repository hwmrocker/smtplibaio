smtplibaio
==========

This is a port of the official python 3.4 smtplib, to make it compatible with asyncio. I converted only `SMTP` and `SMPT_SSL`.

Example

```Python
import asyncio

from smtp import SMTP

try:
    async with SMTP() as client:
        auth = await client.login(username, password)
        client.sendmail(from_addr, to_addr, message)
except ConnectionRefusedError:
    print("Could not connect to SMTP server.")
except ConnectionError:
    print("Some error message")
```
