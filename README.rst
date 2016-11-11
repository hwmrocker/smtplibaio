==========
smtplibaio
==========

The smtplibaio package provides an SMTP client session object that can be used to send e-mail in an asynchronous way (i.e. using ``asyncio``).

Example
=======

.. code-block:: python
    :linenos:
    
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

Current limitations
===================

* STARTTLS is not supported yet,
* Sending Python's ``email.message.Message`` is not supported. You can still use ``email.message.Message.as_string()`` or ``str(email.message.Message)`` instead.:wq

