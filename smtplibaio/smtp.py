#!/usr/bin/env python
# coding: utf-8

"""
SMTP/ESMTP client class.
"""

# Author: The Dragon De Monsyne <dragondm@integral.org>
# ESMTP support, test code and doc fixes added by
#     Eric S. Raymond <esr@thyrsus.com>
# Better RFC 821 compliance (MAIL and RCPT, and CRLF in data)
#     by Carey Evans <c.evans@clear.net.nz>, for picky mail servers.
# RFC 2554 (authentication) support by Gerhard Haering <gerhard@bigfoot.de>.
# Asyncio support by
#     Olaf Gladis <github@gladis.org>
#
# This was modified from the Python 1.5 library HTTP lib.
# This was modified form the Python 3.4 library smtplib.

import asyncio
import base64
import hmac
import re
import socket
import ssl
import errno

from smtplibaio.exceptions import (
    SMTPNoRecipientError,
    SMTPLoginError,
    SMTPAuthenticationError,
    SMTPCommandFailedError,
    BadImplementationError
)

from smtplibaio.streams import SMTPStreamReader, SMTPStreamWriter
from smtplib import quoteaddr


class SMTP:
    """
    SMTP or ESMTP client.

    This should follow RFC 5321 (SMTP), RFC 1869 (ESMTP), RFC 2554 (SMTP
    Authentication) and RFC 2487 (Secure SMTP over TLS).

    Attributes:
        hostname (str): Hostname of the SMTP server we are connecting to.
        port (int): Port on which the SMTP server listens for connections.
        timeout (int): Not used.
        last_helo_response ((int or None, str or None)): A (code, message)
            2-tuple containing the last *HELO* response.
        last_ehlo_response ((int or None, str or None)): A (code, message)
            2-tuple containing the last *EHLO* response.
        supports_esmtp (bool): True if the server supports ESMTP (set after a
            *EHLO* command, False otherwise.
        esmtp_extensions (dict): ESMTP extensions and parameters supported by
            the SMTP server (set after a *EHLO* command).
        auth_mechanisms (list of str): Authentication mechanisms supported by
            the SMTP server.
        ssl_context (bool): Always False. (Used in SMTP_SSL subclass)
        reader (:class:`streams.SMTPStreamReader`): SMTP stream reader, used
            to read server responses.
        writer (:class:`streams.SMTPStreamWriter`): SMTP stream writer, used
            to send commands to the server.
        transport (:class:`asyncio.BaseTransport`): Communication channel
            abstraction between client and server.
        loop (:class:`asyncio.BaseEventLoop`): Event loop to use.
        use_aioopenssl (bool): If True, the connection is made using the
            aioopenssl module. Defaults to False.
        _fqdn (str): Client FQDN. Used to identify the client to the
            server.

    Class Attributes:
        _default_port (int): Default port to use. Defaults to 25.
        _supported_auth_mechanisms (dict): Dict containing the information
            about supported authentication mechanisms, ordered by preference
            of use. The entries consist in :

                - The authentication mechanism name, in lowercase, as given by
                  SMTP servers.
                - The name of the method to call to authenticate using the
                  mechanism.
    """
    _default_port = 25

    _supported_auth_mechanisms = {
        'cram-md5': '_auth_cram_md5',
        'plain': '_auth_plain',
        'login': '_auth_login',
    }

    def __init__(self, hostname='localhost', port=_default_port, fqdn=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT, loop=None,
                 use_aioopenssl=False):
        """
        Initializes a new :class:`SMTP` instance.

        Args:
            hostname (str): Hostname of the SMTP server to connect to.
            port (int): Port to use to connect to the SMTP server.
            fqdn (str or None): Client Fully Qualified Domain Name. This is
                used to identify the client to the server.
            timeout (int): Not used.
            loop (:class:`asyncio.BaseEventLoop`): Event loop to use.
            use_aioopenssl (bool): Use the aioopenssl module to open
                the connection. This is mandatory if you plan on using
                STARTTLS.
        """
        self.hostname = hostname

        try:
            self.port = int(port)
        except ValueError:
            self.port = self.__class__._default_port

        self.timeout = timeout
        self._fqdn = fqdn
        self.loop = loop or asyncio.get_event_loop()
        self.use_aioopenssl = use_aioopenssl

        self.reset_state()

    @property
    def fqdn(self):
        """
        Returns the string used to identify the client when initiating a SMTP
        session.

        RFC 5321 `§ 4.1.1.1`_ and `§ 4.1.3`_ tell us what to do:

        - Use the client FQDN ;
        - If it isn't available, we SHOULD fall back to an address literal.

        Returns:
            str: The value that should be used as the client FQDN.

        .. _`§ 4.1.1.1`: https://tools.ietf.org/html/rfc5321#section-4.1.1.1
        .. _`§ 4.1.3`: https//tools.ietf.org/html/rfc5321#section-4.1.3
        """
        if self._fqdn is None:
            # Let's try to retrieve it:
            self._fqdn = socket.getfqdn()

            if '.' not in self._fqdn:
                try:
                    info = socket.getaddrinfo(host='localhost',
                                              port=None,
                                              proto=socket.IPPROTO_TCP)
                except socket.gaierror:
                    addr = "127.0.0.1"
                else:
                    # We only consider the first returned result and we're
                    # only interested in getting the IP(v4 or v6) address:
                    addr = info[0][4][0]

                self._fqdn = "[{}]".format(addr)

        return self._fqdn

    def reset_state(self):
        """
        Resets some attributes to their default values.

        This is especially useful when initializing a newly created
        :class:`SMTP` instance and when closing an existing SMTP session.

        It allows us to use the same SMTP instance and connect several times.
        """
        self.last_helo_response = (None, None)
        self.last_ehlo_response = (None, None)

        self.supports_esmtp = False
        self.esmtp_extensions = {}

        self.auth_mechanisms = []

        self.ssl_context = False

        self.reader = None
        self.writer = None
        self.transport = None

    async def __aenter__(self):
        """
        Enters the asynchronous context manager.

        Also tries to connect to the server.

        Raises:
            SMTPConnectionRefusedError: If the connection between client and
                SMTP server can not be established.

        .. seealso:: :meth:`SMTP.connect`
        """
        await self.connect()

        return self

    async def __aexit__(self, *args):
        """
        Exits the asynchronous context manager.

        Closes the connection and resets instance attributes.

        .. seealso:: :meth:`SMTP.quit`
        """
        await self.quit()

    async def connect(self):
        """
        Connects to the server.

        .. note:: This method is automatically invoked by
            :meth:`SMTP.__aenter__`. The code is mostly borrowed from the
            :func:`asyncio.streams.open_connection` source code.

        Raises:
            ConnectionError subclass: If the connection between client and
                SMTP server can not be established.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.
        """
        # First build the reader:
        self.reader = SMTPStreamReader(loop=self.loop)

        # Then build the protocol:
        protocol = asyncio.StreamReaderProtocol(self.reader, loop=self.loop)

        # With the just-built reader and protocol, create the connection and
        # get the transport stream:
        conn = {
            'protocol_factory': lambda: protocol,
            'host': self.hostname,
            'port': self.port,
        }

        if self.use_aioopenssl:
            conn.update({
                'use_starttls': not self.ssl_context,
                'ssl_context_factory': lambda transport: self.ssl_context,
                'server_hostname': self.hostname # For SSL
                })

            import aioopenssl
            # This may raise a ConnectionError exception, which we let bubble up.
            self.transport, _ = await aioopenssl.create_starttls_connection(self.loop, **conn)
            # HACK: aioopenssl transports don't implement is_closing, and thus drain() fails...
            self.transport.is_closing = lambda: False
        else:
            conn['ssl'] = self.ssl_context
            # This may raise a ConnectionError exception, which we let bubble up.
            self.transport, _ = await self.loop.create_connection(**conn)

        # If the connection has been established, build the writer:
        self.writer = SMTPStreamWriter(self.transport, protocol, self.reader,
                                       self.loop)

        code, message = await self.reader.read_reply()

        if code != 220:
            raise ConnectionRefusedError(code, message)

        return code, message

    async def do_cmd(self, *args, success=None):
        """
        Sends the given command to the server.

        Args:
            *args: Command and arguments to be sent to the server.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the command fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.
        """
        if success is None:
            success = (250,)

        cmd = " ".join(args)

        await self.writer.send_command(cmd)
        code, message = await self.reader.read_reply()

        if code not in success:
            raise SMTPCommandFailedError(code, message, cmd)

        return code, message

    async def helo(self, from_host=None):
        """
        Sends a SMTP 'HELO' command. - Identifies the client and starts the
        session.

        If given ``from_host`` is None, defaults to the client FQDN.

        For further details, please check out `RFC 5321 § 4.1.1.1`_.

        Args:
            from_host (str or None): Name to use to identify the client.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the server refuses our HELO greeting.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.1`: https://tools.ietf.org/html/rfc5321#section-4.1.1.1
        """
        if from_host is None:
            from_host = self.fqdn

        code, message = await self.do_cmd('HELO', from_host)

        self.last_helo_response = (code, message)

        return code, message

    async def ehlo(self, from_host=None):
        """
        Sends a SMTP 'EHLO' command. - Identifies the client and starts the
        session.

        If given ``from`_host`` is None, defaults to the client FQDN.

        For further details, please check out `RFC 5321 § 4.1.1.1`_.

        Args:
            from_host (str or None): Name to use to identify the client.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the server refuses our EHLO greeting.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.1`: https://tools.ietf.org/html/rfc5321#section-4.1.1.1
        """
        if from_host is None:
            from_host = self.fqdn

        code, message = await self.do_cmd('EHLO', from_host)

        self.last_ehlo_response = (code, message)

        extns, auths = SMTP.parse_esmtp_extensions(message)
        self.esmtp_extensions = extns
        self.auth_mechanisms = auths
        self.supports_esmtp = True

        return code, message

    async def help(self, command_name=None):
        """
        Sends a SMTP 'HELP' command.

        For further details please check out `RFC 5321 § 4.1.1.8`_.

        Args:
            command_name (str or None, optional): Name of a command for which
                you want help. For example, if you want to get help about the
                '*RSET*' command, you'd call ``help('RSET')``.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the HELP command fails.

        Returns:
            Help text as given by the server.

        .. _`RFC 5321 § 4.1.1.8`: https://tools.ietf.org/html/rfc5321#section-4.1.1.8
        """
        if command_name is None:
            command_name = ''

        code, message = await self.do_cmd('HELP', command_name)

        return message

    async def rset(self):
        """
        Sends a SMTP 'RSET' command. - Resets the session.

        For further details, please check out `RFC 5321 § 4.1.1.5`_.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the RSET command fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.5`: https://tools.ietf.org/html/rfc5321#section-4.1.1.5
        """
        return await self.do_cmd('RSET')

    async def noop(self):
        """
        Sends a SMTP 'NOOP' command. - Doesn't do anything.

        For further details, please check out `RFC 5321 § 4.1.1.9`_.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the NOOP command fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.9`: https://tools.ietf.org/html/rfc5321#section-4.1.1.9
        """
        return await self.do_cmd('NOOP')

    async def vrfy(self, address):
        """
        Sends a SMTP 'VRFY' command. - Tests the validity of the given address.

        For further details, please check out `RFC 5321 § 4.1.1.6`_.

        Args:
            address (str): E-mail address to be checked.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the VRFY command fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.6`: https://tools.ietf.org/html/rfc5321#section-4.1.1.6
        """
        return await self.do_cmd('VRFY', address)

    async def expn(self, address):
        """
        Sends a SMTP 'EXPN' command. - Expands a mailing-list.

        For further details, please check out `RFC 5321 § 4.1.1.7`_.

        Args:
            address (str): E-mail address to expand.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the EXPN command fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.7`: https://tools.ietf.org/html/rfc5321#section-4.1.1.7
        """
        return await self.do_cmd('EXPN', address)

    async def mail(self, sender, options=None):
        """
        Sends a SMTP 'MAIL' command. - Starts the mail transfer session.

        For further details, please check out `RFC 5321 § 4.1.1.2`_ and
        `§ 3.3`_.

        Args:
            sender (str): Sender mailbox (used as reverse-path).
            options (list of str or None, optional): Additional options to send
                along with the *MAIL* command.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the MAIL command fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.2`: https://tools.ietf.org/html/rfc5321#section-4.1.1.2
        .. _`§ 3.3`: https://tools.ietf.org/html/rfc5321#section-3.3
        """
        if options is None:
            options = []

        from_addr = "FROM:{}".format(quoteaddr(sender))
        code, message = await self.do_cmd('MAIL', from_addr, *options)

        return code, message

    async def rcpt(self, recipient, options=None):
        """
        Sends a SMTP 'RCPT' command. - Indicates a recipient for the e-mail.

        For further details, please check out `RFC 5321 § 4.1.1.3`_ and
        `§ 3.3`_.

        Args:
            recipient (str): E-mail address of one recipient.
            options (list of str or None, optional): Additional options to send
                along with the *RCPT* command.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the RCPT command fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.3`: https://tools.ietf.org/html/rfc5321#section-4.1.1.3
        .. _`§ 3.3`: https://tools.ietf.org/html/rfc5321#section-3.3
        """
        if options is None:
            options = []

        to_addr = "TO:{}".format(quoteaddr(recipient))
        code, message = await self.do_cmd('RCPT', to_addr, *options)

        return code, message

    async def quit(self):
        """
        Sends a SMTP 'QUIT' command. - Ends the session.

        For further details, please check out `RFC 5321 § 4.1.1.10`_.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response. If the connection is already closed when calling this
                method, returns (-1, None).

        .. _`RFC 5321 § 4.1.1.10`: https://tools.ietf.org/html/rfc5321#section-4.1.1.10
        """
        code = -1
        message = None

        try:
            code, message = await self.do_cmd('QUIT')
        except ConnectionError:
            # We voluntarily ignore this kind of exceptions since... the
            # connection seems already closed.
            pass
        except SMTPCommandFailedError:
            pass

        await self.close()

        return code, message

    async def data(self, email_message):
        """
        Sends a SMTP 'DATA' command. - Transmits the message to the server.

        If ``email_message`` is a bytes object, sends it as it is. Else,
        makes all the required changes so it can be safely trasmitted to the
        SMTP server.`

        For further details, please check out `RFC 5321 § 4.1.1.4`_.

        Args:
            email_message (str or bytes): Message to be sent.

        Raises:
            ConnectionError subclass: If the connection to the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the DATA command fails.

         Returns:
            (int, str): A (code, message) 2-tuple containing the server last
                response (the one the server sent after all data were sent by
                the client).

        .. seealso: :meth:`SMTP.prepare_message`

        .. _`RFC 5321 § 4.1.1.4`: https://tools.ietf.org/html/rfc5321#section-4.1.1.4
        """
        code, message = await self.do_cmd('DATA', success=(354,))

        email_message = SMTP.prepare_message(email_message)

        self.writer.write(email_message)    # write is non-blocking.
        await self.writer.drain()           # don't forget to drain.

        code, message = await self.reader.read_reply()

        return code, message

    async def auth(self, username, password):
        """
        Tries to authenticate user against the SMTP server.

        Args:
            username (str): Username to authenticate with.
            password (str): Password to use along with the given ``username``.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the server refuses our EHLO/HELO
                greeting.
            SMTPLoginError: If the authentication failed (either because all
                attempts failed or because there was no suitable authentication
                mechanism).

        Returns:
            (int, str): A (code, message) 2-tuple containing the last server
                response.
        """
        # EHLO/HELO is required:
        await self.ehlo_or_helo_if_needed()

        errors = []   # To store SMTPAuthenticationErrors
        code = message = None

        # Try to authenticate using all mechanisms supported by both
        # server and client (and only these):
        for auth, meth in self.__class__._supported_auth_mechanisms.items():
            if auth in self.auth_mechanisms:
                auth_func = getattr(self, meth)

                try:
                    code, message = await auth_func(username, password)
                except SMTPAuthenticationError as e:
                    errors.append(e)
                else:
                    break
        else:
            if not errors:
                err = "Could not find any suitable authentication mechanism."
                errors.append(SMTPAuthenticationError(-1, err))

            raise SMTPLoginError(errors)

        return code, message

    async def starttls(self, context=None):
        """
        Upgrades the connection to the SMTP server into TLS mode.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        If the server supports SSL/TLS, this will encrypt the rest of the SMTP
        session.

        Raises:
            SMTPCommandNotSupportedError: If the server does not support STARTTLS.
            SMTPCommandFailedError: If the STARTTLS command fails
            BadImplementationError: If the connection does not use aioopenssl.

        Args:
            context (:obj:`OpenSSL.SSL.Context`): SSL context

        Returns:
            (int, message): A (code, message) 2-tuple containing the server
                response.
        """
        if not self.use_aioopenssl:
            raise BadImplementationError('This connection does not use aioopenssl')

        import aioopenssl
        import OpenSSL

        await self.ehlo_or_helo_if_needed()

        if "starttls" not in self.esmtp_extensions:
            raise SMTPCommandNotSupportedError("STARTTLS not supported.")

        code, message = await self.do_cmd("STARTTLS", success=(220,))
        # Don't check for code, do_cmd did it

        if context is None:
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)

        await self.transport.starttls(ssl_context=context)

        # RFC 3207:
        # The client MUST discard any knowledge obtained from
        # the server, such as the list of SMTP service extensions,
        # which was not obtained from the TLS negotiation itself.

        # FIXME: wouldn't it be better to use reset_state here ?
        # And reset self.reader, self.writer and self.transport just after
        # Maybe also self.ssl_context ?
        self.last_ehlo_response = (None, None)
        self.last_helo_response = (None, None)
        self.supports_esmtp = False
        self.esmtp_extensions = {}
        self.auth_mechanisms = []

        return (code, message)

    async def sendmail(self, sender, recipients, message, mail_options=None,
                       rcpt_options=None):
        """
        Performs an entire e-mail transaction.

        Example:

            >>> try:
            >>>     with SMTP() as client:
            >>>         try:
            >>>             r = client.sendmail(sender, recipients, message)
            >>>         except SMTPException:
            >>>             print("Error while sending message.")
            >>>         else:
            >>>             print("Result: {}.".format(r))
            >>> except ConnectionError as e:
            >>>     print(e)
            Result: {}.

        Args:
            sender (str): E-mail address of the sender.
            recipients (list of str or str): E-mail(s) address(es) of the
                recipient(s).
            message (str or bytes): Message body.
            mail_options (list of str): ESMTP options (such as *8BITMIME*) to
                send along the *MAIL* command.
            rcpt_options (list of str): ESMTP options (such as *DSN*) to
                send along all the *RCPT* commands.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the server refuses our EHLO/HELO
                greeting.
            SMTPCommandFailedError: If the server refuses our MAIL command.
            SMTPCommandFailedError: If the server refuses our DATA command.
            SMTPNoRecipientError: If the server refuses all given
                recipients.

        Returns:
            dict: A dict containing an entry for each recipient that was
                refused. Each entry is associated with  a (code, message)
                2-tuple containing the error code and message, as returned by
                the server.

                When everythign runs smoothly, the returning dict is empty.

        .. note:: The connection remains open after. It's your responsibility
            to close it. A good practice is to use the asynchronous context
            manager instead. See :meth:`SMTP.__aenter__` for further details.
        """
        # Make sure `recipients` is a list:
        if isinstance(recipients, str):
            recipients = [recipients]

        # Set some defaults values:
        if mail_options is None:
            mail_options = []

        if rcpt_options is None:
            rcpt_options = []

        # EHLO or HELO is required:
        await self.ehlo_or_helo_if_needed()

        if self.supports_esmtp:
            if "size" in self.esmtp_extensions:
                mail_options.append("size={}".format(len(message)))

        await self.mail(sender, mail_options)

        errors = []

        for recipient in recipients:
            try:
                await self.rcpt(recipient, rcpt_options)
            except SMTPCommandFailedError as e:
                errors.append(e)

        if len(recipients) == len(errors):
            # The server refused all our recipients:
            raise SMTPNoRecipientError(errors)

        await self.data(message)

        # If we got here then somebody got our mail:
        return errors

    async def send_mail(self, sender, recipients, message, mail_options=None,
                        rcpt_options=None):
        """
        Alias for :meth:`SMTP.sendmail`.
        """
        return await self.sendmail(sender, recipients, message,
                                   mail_options, rcpt_options)

    async def ehlo_or_helo_if_needed(self):
        """
        Calls :meth:`SMTP.ehlo` and/or :meth:`SMTP.helo` if needed.

        If there hasn't been any previous *EHLO* or *HELO* command this
        session, tries to initiate the session. *EHLO* is tried first.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPCommandFailedError: If the server refuses our EHLO/HELO
                greeting.
        """
        no_helo = self.last_helo_response == (None, None)
        no_ehlo = self.last_ehlo_response == (None, None)

        if no_helo and no_ehlo:
            try:
                # First we try EHLO:
                await self.ehlo()
            except SMTPCommandFailedError:
                # EHLO failed, let's try HELO:
                await self.helo()

    async def close(self):
        """
        Cleans up after the connection to the SMTP server has been closed
        (voluntarily or not).
        """
        if self.writer is not None:
            # Close the transport:
            try:
                self.writer.close()
            except OSError as exc:
                if exc.errno != errno.ENOTCONN:
                    raise

        self.reset_state()

    async def _auth_cram_md5(self, username, password):
        """
        Performs an authentication attemps using the CRAM-MD5 mechanism.

        Protocol:

            1. Send 'AUTH CRAM-MD5' to server ;
            2. If the server replies with a 334 return code, we can go on:

                1) The challenge (sent by the server) is base64-decoded ;
                2) The decoded challenge is hashed using HMAC-MD5 and the user
                   password as key (shared secret) ;
                3) The hashed challenge is converted to a string of lowercase
                   hexadecimal digits ;
                4) The username and a space character are prepended to the hex
                   digits ;
                5) The concatenation is base64-encoded and sent to the server.
                6) If the server replies with a return code of 235, user is
                   authenticated.

        Args:
            username (str): Identifier of the user trying to authenticate.
            password (str): Password for the user.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPAuthenticationError: If the authentication attempt fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.
        """
        mechanism = 'CRAM-MD5'

        code, message = await self.do_cmd('AUTH', mechanism, success=(334,))

        decoded_challenge = base64.b64decode(message)

        challenge_hash = hmac.new(key=password.encode('utf-8'),
                                  msg=decoded_challenge,
                                  digestmod='md5')

        hex_hash = challenge_hash.hexdigest()
        response = "{} {}".format(username, hex_hash)
        encoded_response = SMTP.b64enc(response)

        try:
            code, message = await self.do_cmd(encoded_response,
                                              success=(235, 503))
        except SMTPCommandFailedError as e:
            raise SMTPAuthenticationError(e.code, e.message, mechanism)

        return code, message

    async def _auth_login(self, username, password):
        """
        Performs an authentication attempt using the LOGIN mechanism.

        Protocol:

            1. The username is base64-encoded ;
            2. The string 'AUTH LOGIN' and a space character are prepended to
               the base64-encoded username and sent to the server ;
            3. If the server replies with a 334 return code, we can go on:

                1) The password is base64-encoded and sent to the server ;
                2) If the server replies with a 235 return code, the user is
                   authenticated.

        Args:
            username (str): Identifier of the user trying to authenticate.
            password (str): Password for the user.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPAuthenticationError: If the authentication attempt fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.
        """
        mechanism = 'LOGIN'

        code, message = await self.do_cmd('AUTH', mechanism,
                                          SMTP.b64enc(username),
                                          success=(334,))

        try:
            code, message = await self.do_cmd(SMTP.b64enc(password),
                                              success=(235, 503))
        except SMTPCommandFailedError as e:
            raise SMTPAuthenticationError(e.code, e.message, mechanism)

        return code, message

    async def _auth_plain(self, username, password):
        """
        Performs an authentication attempt using the PLAIN mechanism.

        Protocol:

            1. Format the username and password in a suitable way ;
            2. The formatted string is base64-encoded ;
            3. The string 'AUTH PLAIN' and a space character are prepended to
               the base64-encoded username and password and sent to the
               server ;
            4. If the server replies with a 235 return code, user is
               authenticated.

        Args:
            username (str): Identifier of the user trying to authenticate.
            password (str): Password for the user.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPAuthenticationError: If the authentication attempt fails.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.
        """
        mechanism = 'PLAIN'

        credentials = "\0{}\0{}".format(username, password)
        encoded_credentials = SMTP.b64enc(credentials)

        try:
            code, message = await self.do_cmd('AUTH', mechanism,
                                              encoded_credentials,
                                              success=(235, 503))
        except SMTPCommandFailedError as e:
            raise SMTPAuthenticationError(e.code, e.message, mechanism)

        return code, message

    @staticmethod
    def parse_esmtp_extensions(message):
        """
        Parses the response given by an ESMTP server after a *EHLO* command.

        The response is parsed to build:

        - A dict of supported ESMTP extensions (with parameters, if any).
        - A list of supported authentication methods.

        Returns:
            (dict, list): A (extensions, auth_mechanisms) 2-tuple containing
                the supported extensions and authentication methods.
        """
        extns = {}
        auths = []

        oldstyle_auth_regex = re.compile(r"auth=(?P<auth>.*)", re.IGNORECASE)

        extension_regex = re.compile(r"(?P<feature>[a-z0-9][a-z0-9\-]*) ?",
                                     re.IGNORECASE)

        lines = message.splitlines()

        for line in lines[1:]:
            # To be able to communicate with as many SMTP servers as possible,
            # we have to take the old-style auth advertisement into account.
            match = oldstyle_auth_regex.match(line)

            if match:
                auth = match.group("auth")[0]
                auth = auth.lower().strip()

                if auth not in auths:
                    auths.append(auth)

            # RFC 1869 requires a space between EHLO keyword and parameters.
            # It's actually stricter, in that only spaces are allowed between
            # parameters, but were not going to check for that here.
            # Note that the space isn't present if there are no parameters.
            match = extension_regex.match(line)

            if match:
                feature = match.group("feature").lower()
                params = match.string[match.end("feature"):].strip()

                extns[feature] = params

                if feature == "auth":
                    auths.extend([param.strip().lower()
                                  for param
                                  in params.split()])

        return extns, auths

    @staticmethod
    def prepare_message(message):
        """
        Returns the given message encoded in ascii with a format suitable for
        SMTP transmission:

        - Makes sure the message is ASCII encoded ;
        - Normalizes line endings to '\r\n' ;
        - Adds a (second) period at the beginning of lines that start
          with a period ;
        - Makes sure the message ends with '\r\n.\r\n'.

        For further details, please check out RFC 5321 `§ 4.1.1.4`_
        and `§ 4.5.2`_.

        .. _`§ 4.1.1.1`: https://tools.ietf.org/html/rfc5321#section-4.1.1.4
        .. _`§ 4.5.2`: https://tools.ietf.org/html/rfc5321#section-4.5.2
        """
        if isinstance(message, bytes):
            bytes_message = message
        else:
            bytes_message = message.encode("ascii")

        # The original algorithm uses regexes to do this stuff.
        # This one is -IMHO- more pythonic and it is slightly faster.
        #
        # Another version is even faster, but I chose to keep something
        # more pythonic and readable.
        # FYI, the fastest way to do all this stuff seems to be
        # (according to my benchmarks):
        #
        # bytes_message.replace(b"\r\n", b"\n") \
        #              .replace(b"\r", b"\n") \
        #              .replace(b"\n", b"\r\n")
        #
        # DOT_LINE_REGEX = re.compile(rb"^\.", re.MULTILINE)
        # bytes_message = DOT_LINE_REGEX.sub(b"..", bytes_message)
        #
        # if not bytes_message.endswith(b"\r\n"):
        #     bytes_message += b"\r\n"
        #
        # bytes_message += b"\r\n.\r\n"

        lines = []

        for line in bytes_message.splitlines():
            if line.startswith(b"."):
                line = line.replace(b".", b"..", 1)

            lines.append(line)

        # Recompose the message with <CRLF> only:
        bytes_message = b"\r\n".join(lines)

        # Make sure message ends with <CRLF>.<CRLF>:
        bytes_message += b"\r\n.\r\n"

        return bytes_message

    @staticmethod
    def b64enc(s):
        """
        Base64-encodes the given string and returns it as a :obj:`str`.

        This is a simple helper function that takes a str, base64-encodes it
        and returns it as str.
        :mod:`base64` functions are working with :obj:`bytes`, hence this func.

        Args:
            s (str): String to be converted to base64.

        Returns:
            str: A base64-encoded string.
        """
        return base64.b64encode(s.encode('utf-8')).decode('utf-8')

    @staticmethod
    def b64dec(b):
        """
        Base64-decodes the given :obj:`bytes` and converts it to a :obj:`str`.

        This is a simple helper function that takes a bytes, base64-decodes it
        and returns it as str.
        :mod:`base64` functions are working with :obj:`bytes`, hence this func.

        Args:
            b (bytes): A base64-encoded bytes.

        Returns:
            str: A base64-decoded string.
        """
        return base64.b64decode(b).decode('utf-8')


class SMTP_SSL(SMTP):
    """
    SMTP or ESMTP client over an SSL channel.

    Attributes:
        ssl_context (:class:`OpenSSL.SSL.Context`): SSL context to use to establish
            the connection with the SMTP server.

    .. seealso: :class:`SMTP`
    """
    _default_port = 465

    def __init__(self, hostname='localhost', port=_default_port, fqdn=None,
                 context=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 use_aioopenssl=False):
        """
        Initializes a new :class:`SMTP_SSL` instance.

        Sets a real SSL context. If given ``context`` is None, tries to
        create a suitable context.

        Also default port in this case is *465*.

        .. seealso:: :meth:`SMTP.__init__`
        """
        super().__init__(hostname, port, fqdn, timeout, use_aioopenssl=use_aioopenssl)

        if context is None:
            if use_aioopenssl:
                import OpenSSL
                context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            else:
                context = ssl.create_default_context()

        self.ssl_context = context
