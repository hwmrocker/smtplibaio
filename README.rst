==========
smtplibaio
==========

The smtplibaio package provides an SMTP client session object that can be used to send e-mail in an asynchronous way (i.e. using ``asyncio``).

Example
=======

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
            client.sendmail(from_addr, to_addr, message)
    
    
    if __name__ == '__main__':
        loop = asyncio.get_event_loop()
        loop.run_until_complete(send_email())
        loop.close()

As you can see, the Asynchronous Context Manager makes it really easy to use.

You can also have a more fine-grained control using the lower-level methods.

Supported SMTP commands
=======================

* EHLO (``SMTP.ehlo()``) ;
* HELO (``SMTP.helo()``) ;
* AUTH (``SMTP.auth()``) (*LOGIN*, *PLAIN* and *CRAM-MD5* mechanisms are suported) ;
* MAIL FROM (``SMTP.mail()``) ;
* RCPT TO (``SMTP.rcpt()``) ;
* VRFY (``SMTP.vrfy()``) ;
* DATA (``SMTP.data()``) ;
* EXPN (``SMTP.expn()``) ;
* NOOP (``SMTP.noop()``) ;
* QUIT (``SMTP.quit()``) ;
* HELP (``SMTP.help()``).

Current limitations
===================

* STARTTLS is not supported yet,
* There is no direct support for Python's ``email.message.Message``. You can still use ``email.message.Message.as_string()`` or ``str(email.message.Message)`` instead.
