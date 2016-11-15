==========
smtplibaio
==========

The smtplibaio package provides an SMTP client session object that can be used to send e-mail in an asynchronous way (i.e. using ``asyncio``).

Examples
========

.. code-block:: python
    
    import asyncio
    
    from smtp import SMTP
    
    
    async def send_email():
        """
        """
        from_addr = "bob@example.net"
        to_addr = "alice@example.org"
    
        message = "Hi Alice !"
    
        async with SMTP() as client:
            await client.sendmail(from_addr, to_addr, message)
    
    
    if __name__ == '__main__':
        loop = asyncio.get_event_loop()
        loop.run_until_complete(send_email())
        loop.close()

As you can see, the Asynchronous Context Manager makes it really easy to use.

You can also use objects provided by the ``email`` package, available in the
Python Standard Library (i.e. ``email.message.EmailMessage``):

.. code-block:: python
    
    import asyncio
    
    from email.message import EmailMessage
    from email.headerregistry import Address
    
    
    async def send_email():
        """
        """
        # Credentials used to authenticate:
        username = "alice"
        passwd = "5ecreT!"
    
        # Use of Address class is not mandatory:
        from_addr = str(Address("Alice", "alice", "example.org"))
        to_addr = str(Address("Bob", "bob", "example.net"))
        bcc_addr = str(Address("John", "john", "example.net"))
    
        subject = "Testing smtplibaio"
        content = "Look, all emails sent from this method are BCCed to John !"
    
        # Build the list of recipients (To + Bcc):
        recipients = [to_addr, bcc_addr]
    
        # Build the EmailMessage object:
        message = EmailMessage()
        message.add_header("From", from_addr)
        message.add_header("To", to_addr)
        message.add_header("Bcc", bcc_addr)
        message.add_header("Subject", subject)
        message.add_header("Content-type", "text/plain", charset="utf-8")
        message.set_content(content)
    
        # Send the e-mail:
        async with SMTP() as client:
            await client.auth(username, passwd)
            await client.sendmail(from_addr, recipients, message.as_string())
    
    
    if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.run_until_complete(send_email())
        loop.close()

You can also have a more fine-grained control using the lower-level methods.


Supported SMTP commands
=======================

* EHLO - ``SMTP.ehlo()`` ;
* HELO - ``SMTP.helo()`` ;
* AUTH - ``SMTP.auth()`` (*LOGIN*, *PLAIN* and *CRAM-MD5* mechanisms are suported) ;
* MAIL FROM - ``SMTP.mail()`` ;
* RCPT TO - ``SMTP.rcpt()`` ;
* VRFY - ``SMTP.vrfy()`` ;
* DATA - ``SMTP.data()`` ;
* EXPN - ``SMTP.expn()`` ;
* NOOP - ``SMTP.noop()`` ;
* QUIT - ``SMTP.quit()`` ;
* HELP - ``SMTP.help()``.

Current limitations
===================

* STARTTLS is not supported yet,
* There is no direct support for Python's ``email.message.EmailMessage``. You can still use ``email.message.EmailMessage.as_string()`` or ``str(email.message.EmailMessage)`` instead. See the example above for further details.
