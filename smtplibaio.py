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
import socket
import io
import re
import email.utils
import email.message
import email.generator
import base64
import hmac
import copy
import ssl

from email.base64mime import body_encode as encode_base64
from sys import stderr

from exceptions import (
    SMTPCommandNotSupportedError,
    SMTPSenderRefusedError,
    SMTPRecipientRefusedError,
    SMTPAllRecipientsRefusedError,
    SMTPDataRefusedError,
    SMTPHelloRefusedError,
    SMTPAuthenticationError,
)
from streams import SMTPStreamReader, SMTPStreamWriter


OLDSTYLE_AUTH_REGEX = re.compile(r"auth=(?P<auth>.*)",
                                 re.IGNORECASE)
EXTENSION_REGEX = re.compile(r"(?P<feature>[a-z0-9][a-z0-9\-]*) ?",
                             re.IGNORECASE)


def quoteaddr(addrstring):
    """Quote a subset of the email addresses defined by RFC 821.

    Should be able to handle anything email.utils.parseaddr can handle.
    """
    displayname, addr = email.utils.parseaddr(addrstring)
    if (displayname, addr) == ('', ''):
        # parseaddr couldn't parse it, use it as is and hope for the best.
        if addrstring.strip().startswith('<'):
            return addrstring
        return "<%s>" % addrstring
    return "<%s>" % addr


def _addr_only(addrstring):
    displayname, addr = email.utils.parseaddr(addrstring)
    if (displayname, addr) == ('', ''):
        # parseaddr couldn't parse it, so use it as is.
        return addrstring
    return addr


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
        auth_methods (list of str): Authentication methods supported by the
            SMTP server.
        ssl_context (bool): Always False. (Used in SMTP_SSL subclass)
        reader (:class:`streams.SMTPStreamReader`): SMTP stream reader, used to
            read server responses.
        writer (:class:`streams.SMTPStreamWriter`): SMTP stream writer, used to
            send commands to the server.
        transport (:class:`asyncio.BaseTransport`): Communication channel
            abstraction between client and server.
        loop (:class:`asyncio.BaseEventLoop`): Event loop to use.
        _fqdn (str): Client FQDN. Used to identify the client to the
            server.

    Class Attributes:
        default_port (int): Default port to use. Defaults to 25.
        debug_level (int): Level of output. Any value > 0 will make the class
            print information.
    """
    default_port = 25
    debug_level = 0

    def __init__(self, hostname='localhost', port=default_port, fqdn=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT, loop=None):
        """
        Initializes a new :class:`SMTP` instance.

        Args:
            hostname (str): Hostname of the SMTP server to connect to. Defaults
                to *localhost*.
            port (int): Port to use to connect to the SMTP server. Defaults
                to *25*
            fqdn (str or None): Client Fully Qualified Domain Name. This is used
                to identify the client to the server. Defaults to None.
            timeout (int): Not used.
            loop (:class:`asyncio.BaseEventLoop`): Event loop to use.
        """
        self.hostname = hostname

        try:
            self.port = int(port)
        except ValueError:
            self.port = self.__class__._default_port

        self.timeout = timeout
        self._fqdn = fqdn
        self.loop = loop or asyncio.get_event_loop()

        self.reset_state()

    @property
    def fqdn(self):
        """
        Returns the string used to identify the client when initiating a SMTP
        session.

        RFC 5321 tells us what to do:

        - Use the client FQDN ;
        - If it isn't available, we SHOULD fall back to an address literal.

        Returns:
            str: The value that should be used as the client FQDN.
        """
        if self._fqdn is None:
            # Let's try to retrieve it:
            self._fqdn = socket.getfqdn()

            if '.' not in self._fqdn:
                # FQDN doesn't seem to be valid, fall back to address literal,
                # See RFC 5321 § 4.1.1.1 and § 4.1.3
                try:
                    info = socket.getaddrinfo(host='localhost',
                                              port=None,
                                              proto=socket.IPPROTO_TCP)
                except socket.gaierror:
                    addr = "127.0.0.1"
                else:
                    # We only consider the first returned result and we're only
                    # interested in getting the IP(v4 or v6) address:
                    addr = info[0][4][0]

                self._fqdn = "[{}]".format(addr)

        if self.__class__.debug_level > 0:
            print("FQDN: {0}".format(self._fqdn), file=stderr)

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

        self.auth_methods = []

        self.ssl_context = False

        self.reader = None
        self.writer = None
        self.transport = None
        self.protocol = None

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
        if self.__class__.debug_level > 0:
            print("Connect: {0}"
                  .format((self.hostname, self.port)),
                  file=stderr)

        # First build the reader:
        self.reader = SMTPStreamReader(loop=self.loop)

        # Then build the protocol:
        # protocol = SMTPStreamReaderProtocol(self.reader, loop=self.loop)
        protocol = asyncio.StreamReaderProtocol(self.reader, loop=self.loop)

        # With the just-built reader and protocol, create the connection and
        # get the transport stream:
        conn = {
            'protocol_factory': lambda: protocol,
            'host': self.hostname,
            'port': self.port,
            'ssl': self.ssl_context
        }

        # This may raise a ConnectionError exception, which we let bubble up.
        self.transport, _ = await self.loop.create_connection(**conn)

        # If the connection has been established, build the writer:
        self.writer = SMTPStreamWriter(self.transport, protocol, self.reader,
                                       self.loop)

        code, message = await self.reader.read_reply()

        if self.__class__.debug_level > 0:
            print("Reply: code: {} - msg: {}".format(code, message),
                  file=stderr)

        if code != 220:
            raise ConnectionRefusedError(code, message)

        return code, message

    async def do_cmd(self, *args):
        """
        Sends the given command to the server.

        Args:
            *args: Command and arguments to be sent to the server.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.
        """
        if self.__class__.debug_level > 0:
            print("Send: {0}".format(" ".join(args)), file=stderr)

        await self.writer.send_command(*args)
        code, message = await self.reader.read_reply()

        if self.__class__.debug_level > 0:
            print("Reply: code: {} - msg: {}".format(code, message),
                  file=stderr)

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
            SMTPHelloRefusedError: If the server refuses our HELO greeting.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.1`: https://tools.ietf.org/html/rfc5321#section-4.1.1.1
        """
        if from_host is None:
            from_host = self.fqdn

        code, message = await self.do_cmd('HELO', from_host)
        self.last_helo_response = (code, message)

        if code != 250:
            raise SMTPHelloRefusedError(code, message)

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
            SMTPHelloRefusedError: If the server refuses our EHLO greeting.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.1`: https://tools.ietf.org/html/rfc5321#section-4.1.1.1
        """
        if from_host is None:
            from_host = self.fqdn

        code, message = await self.do_cmd('EHLO', from_host)
        self.last_ehlo_response = (code, message)

        if code != 250:
            raise SMTPHelloRefusedError(code, message)

        extns, auths = SMTP.parse_esmtp_extensions(message)
        self.esmtp_extensions = extns
        self.auth_methods = auths
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

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.6`: https://tools.ietf.org/html/rfc5321#section-4.1.1.6
        """
        return await self.do_cmd('VRFY', _addr_only(address))

    async def expn(self, address):
        """
        Sends a SMTP 'EXPN' command. - Expands a mailing-list.

        For further details, please check out `RFC 5321 § 4.1.1.7`_.

        Args:
            address (str): E-mail address to expand.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.7`: https://tools.ietf.org/html/rfc5321#section-4.1.1.7
        """
        return await self.do_cmd('EXPN', _addr_only(address))

    async def mail(self, sender, options=None):
        """
        Sends a SMTP 'MAIL' command. - Starts the mail transfer session.

        For further details, please check out `RFC 5321 § 4.1.1.2`_.

        Args:
            sender (str): Sender mailbox (used as reverse-path).
            options (list of str or None, optional): Additional options to send
                along with the *MAIL* command.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPSenderRefusedError: If the server refuses the given sender
                e-mail address.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.2`: https://tools.ietf.org/html/rfc5321#section-4.1.1.2
        """
        if options is None:
            options = []

        # FIXME: check if options are supported by server.
        #        only pass supported options.

        from_addr = "FROM:{}".format(quoteaddr(sender))

        code, message = await self.do_cmd('MAIL', from_addr, *options)

        if code != 250:
            raise SMTPSenderRefusedError(code, message)

        return code, message

    async def rcpt(self, recipient, options=None):
        """
        Sends a SMTP 'RCPT' command. - Indicates a recipient for the e-mail.

        For further details, please check out `RFC 5321 § 4.1.1.3`_.

        Args:
            recipient (str): E-mail address of one recipient.
            options (list of str or None, optional): Additional options to send 
                along with the *RCPT* command.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPRecipientRefusedError: If the server refuses the given
                recipient e-mail address.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.

        .. _`RFC 5321 § 4.1.1.3`: https://tools.ietf.org/html/rfc5321#section-4.1.1.3
        """
        if options is None:
            options = []

        # FIXME: check if options are supported by server.
        #        only pass supported options.

        to_addr = "TO:{}".format(quoteaddr(recipient))

        code, message = await self.do_cmd('RCPT', to_addr, *options)

        if code != 250:  # FIXME: be more precise.
            raise SMTPRecipientRefusedError(code, message)

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
            # connection seems already down.
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
            SMTPDataRefusedError: If the server refuses to handle the given
                data.
            ConnectionError subclass: If the connection to the server is
                unexpectedely lost.

         Returns:
            (int, str): A (code, message) 2-tuple containing the server last
                response (the one the server sent after all data were sent by
                the client).

        .. seealso: :meth:`SMTP.prepare_message`

        .. _`RFC 5321 § 4.1.1.4`: https://tools.ietf.org/html/rfc5321#section-4.1.1.4
        """
        code, message = await self.do_cmd('DATA')

        if self.__class__.debug_level > 0:
            print("DATA: {} {}".format(code, message), file=stderr)

        # Check intermediate server reply:
        if code != 354:
            raise SMTPDataRefusedError(code, message)

        email_message = SMTP.prepare_message(email_message)

        self.writer.write(email_message)    # write is non-blocking.
        await self.writer.drain()           # don't forget to drain.

        code, message = await self.reader.read_reply()

        if self.__class__.debug_level > 0:
            print("DATA: {} {}".format(code, message), file=stderr)

        if code != 250:
            raise SMTPDataRefusedError(code, message)

        return code, message

    async def login(self, username, password):
        """
        Logs in on an SMTP server that requires authentication.

        Args:
            username (str): Username to authenticate with.
            password (str): Password to use along with the given ``username``.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPHelloRefusedError: If the server refuses our EHLO/HELO
                greeting.
            SMTPAuthenticationError: If the server rejects the
                username/password combination.
            SMTPException: If there is no suitable authentication method
                available.

        Returns:
            (int, str): A (code, message) 2-tuple containing the server
                response.
        """
        def encode_cram_md5(challenge, user, password):
            challenge = base64.decodebytes(challenge)
            response = user + " " + hmac.HMAC(password.encode('ascii'),
                                              challenge, 'md5').hexdigest()

            return encode_base64(response.encode('ascii'), eol='')

        def encode_plain(user, password):
            s = "\0%s\0%s" % (user, password)

            return encode_base64(s.encode('ascii'), eol='')

        AUTH_PLAIN = "PLAIN"
        AUTH_CRAM_MD5 = "CRAM-MD5"
        AUTH_LOGIN = "LOGIN"

        await self.ehlo_or_helo_if_needed()

        if "auth" not in self.esmtp_extensions:
            err = "SMTP AUTH extension not supported."
            raise SMTPCommandNotSupportedError(-1, err)

        # Authentication methods the server claims to support
        advertised_authlist = self.esmtp_features["auth"].split()

        # List of authentication methods we support: from preferred to
        # less preferred methods. Except for the purpose of testing the weaker
        # ones, we prefer stronger methods like CRAM-MD5:
        preferred_auths = [AUTH_CRAM_MD5, AUTH_PLAIN, AUTH_LOGIN]

        # We try the authentication methods the server advertises, but only the
        # ones *we* support. And in our preferred order.
        authlist = [auth for auth in preferred_auths if auth in advertised_authlist]

        if not authlist:
            raise SMTPException("No suitable authentication method found.")

        # Some servers advertise authentication methods they don't really
        # support, so if authentication fails, we continue until we've tried
        # all methods.
        for authmethod in authlist:
            if authmethod == AUTH_CRAM_MD5:
                code, resp = await self.do_cmd("AUTH", AUTH_CRAM_MD5)

                if code == 334:
                    cmd = encode_cram_md5(resp, user, password)
                    code, resp = await self.do_cmd(cmd)

            elif authmethod == AUTH_PLAIN:
                cmd = "{0} {1}".format(AUTH_PLAIN,
                                       encode_plain(user, password))
                code, resp = await self.do_cmd("AUTH", cmd)

            elif authmethod == AUTH_LOGIN:
                cmd = "{0} {1}".format(AUTH_LOGIN,
                                       encode_base64(user.encode('ascii'),
                                                     eol=''))
                code, resp = await self.do_cmd("AUTH", cmd)

                if code == 334:
                    cmd = encode_base64(password.encode('ascii'), eol='')
                    code, resp = await self.do_cmd(cmd)

            # 235 == 'Authentication successful'
            # 503 == 'Error: already authenticated'
            if code in (235, 503):
                return (code, resp)

        # We could not login sucessfully. Return result of last attempt.
        raise SMTPAuthenticationError(code, resp)

    async def starttls(self, keyfile=None, certfile=None, context=None):
        """Puts the connection to the SMTP server into TLS mode.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        If the server supports TLS, this will encrypt the rest of the SMTP
        session. If you provide the keyfile and certfile parameters,
        the identity of the SMTP server and client can be checked. This,
        however, depends on whether the socket module really checks the
        certificates.

        This method may raise the following exceptions:

         SMTPHeloError            The server didn't reply properly to
                                  the helo greeting.
        """
        await self.ehlo_or_helo_if_needed()

        if "starttls" not in self.esmtp_extensions:
            err = "STARTTLS extension not supported."
            raise SMTPCommandNotSupportedError(err)

        resp, reply = await self.do_cmd("STARTTLS")

        if resp == 220:
            if not _have_ssl:
                raise RuntimeError("No SSL support included in this Python")

            if context is not None and keyfile is not None:
                raise ValueError("context and keyfile arguments are mutually "
                                 "exclusive")

            if context is not None and certfile is not None:
                raise ValueError("context and certfile arguments are mutually "
                                 "exclusive")

            if context is None:
                context = ssl._create_stdlib_context(certfile=certfile,
                                                     keyfile=keyfile)

            self.sock = context.wrap_socket(self.sock,
                                            server_hostname=self._host)

            self.file = None
            # RFC 3207:
            # The client MUST discard any knowledge obtained from
            # the server, such as the list of SMTP service extensions,
            # which was not obtained from the TLS negotiation itself.
            self.helo_resp = None
            self.ehlo_resp = None
            self.esmtp_features = {}
            self.does_esmtp = 0

        return (resp, reply)

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
            SMTPHelloRefusedError: If the server refuses our EHLO/HELO
                greeting.
            SMTPSenderRefusedError: If the server refuses the given sender
                e-mail address.
            SMTPAllRecipientsRefusedError: If the server refuses all given
                recipients.
            SMTPDataRefusedError: If the server refuses to handle the given
                message.

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

        # This may raise an SMTPSenderRefusedError:
        await self.mail(sender, mail_options)

        errors = {}

        for recipient in recipients:
            try:
                await self.rcpt(recipient, rcpt_options)
            except SMTPRecipientRefusedError as e:
                errors[recipient] = (e.code, e.message)

        if len(recipients) == len(errors):
            # The server refused all our recipients:
            raise SMTPAllRecipientsRefusedError(errors)

        # This may raise an SMTPDataRefusedError:
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

    async def send_message(self, msg, from_addr=None, to_addrs=None,
                     mail_options=[], rcpt_options={}):
        """Converts message to a bytestring and passes it to sendmail.

        The arguments are as for sendmail, except that msg is an
        email.message.Message object.  If from_addr is None or to_addrs is
        None, these arguments are taken from the headers of the Message as
        described in RFC 2822 (a ValueError is raised if there is more than
        one set of 'Resent-' headers).  Regardless of the values of from_addr and
        to_addr, any Bcc field (or Resent-Bcc field, when the Message is a
        resent) of the Message object won't be transmitted.  The Message
        object is then serialized using email.generator.BytesGenerator and
        sendmail is called to transmit the message.

        """
        # 'Resent-Date' is a mandatory field if the Message is resent (RFC 2822
        # Section 3.6.6). In such a case, we use the 'Resent-*' fields.  However,
        # if there is more than one 'Resent-' block there's no way to
        # unambiguously determine which one is the most recent in all cases,
        # so rather than guess we raise a ValueError in that case.
        #
        # TODO implement heuristics to guess the correct Resent-* block with an
        # option allowing the user to enable the heuristics.  (It should be
        # possible to guess correctly almost all of the time.)

        resent = msg.get_all('Resent-Date')
        if resent is None:
            header_prefix = ''
        elif len(resent) == 1:
            header_prefix = 'Resent-'
        else:
            raise ValueError("message has more than one 'Resent-' header block")

        if from_addr is None:
            # Prefer the sender field per RFC 2822:3.6.2.
            from_addr = (msg[header_prefix + 'Sender']
                         if (header_prefix + 'Sender') in msg
                         else msg[header_prefix + 'From'])

        if to_addrs is None:
            addr_fields = [f for f in (msg[header_prefix + 'To'],
                                       msg[header_prefix + 'Bcc'],
                                       msg[header_prefix + 'Cc']) if f is not None]
            to_addrs = [a[1] for a in email.utils.getaddresses(addr_fields)]
        # Make a local copy so we can delete the bcc headers.
        msg_copy = copy.copy(msg)
        del msg_copy['Bcc']
        del msg_copy['Resent-Bcc']

        with io.BytesIO() as bytesmsg:
            g = email.generator.BytesGenerator(bytesmsg)
            g.flatten(msg_copy, linesep='\r\n')
            flatmsg = bytesmsg.getvalue()

        return (await self.sendmail(from_addr, to_addrs, flatmsg,
                                         mail_options, rcpt_options))

    async def ehlo_or_helo_if_needed(self):
        """
        Calls :meth:`SMTP.ehlo` and/or :meth:`SMTP.helo` if needed.

        If there hasn't been any previous *EHLO* or *HELO* command this session,
        tries to initiate the session. *EHLO* is tried first.

        Raises:
            ConnectionResetError: If the connection with the server is
                unexpectedely lost.
            SMTPHelloRefusedError: If the server refuses our EHLO/HELO
                greeting.
        """
        no_helo = self.last_helo_response == (None, None)
        no_ehlo = self.last_ehlo_response == (None, None)

        if no_helo and no_ehlo:
            try:
                # First we try EHLO:
                await self.ehlo()
            except ConnectionRefusedError:
                # EHLO failed, let's try HELO:
                await self.helo()

    async def close(self):
        """
        Cleans up after the connection to the SMTP server has been closed
        (voluntarily or not).
        """
        if self.writer is not None:
            # Close the transport:
            self.writer.close()

        self.reset_state()

    @classmethod
    def set_debuglevel(cls, debuglevel):
        """
        Sets the debug output level to ``debuglevel``.
        """
        cls.debug_level = debuglevel

    @staticmethod
    def parse_esmtp_extensions(message):
        """
        Parses the response given by an ESMTP server after a *EHLO* command.

        The response is parsed to build:

        - A dict of supported ESMTP extensions (with parameters, if any).
        - A list of supported authentication methods.

        Returns:
            (dict, list): A (extensions, auth_methods) 2-tuple containing the
                supported extensions and authentication methods.
        """
        extns = {}
        auths = []

        lines = message.splitlines()

        for line in lines[1:]:
            # To be able to communicate with as many SMTP servers as possible,
            # we have to take the old-style auth advertisement into account.
            match = OLDSTYLE_AUTH_REGEX.match(line)

            if match:
                auth = match.group("auth")[0]
                auth = auth.lower().strip()

                if auth not in auths:
                    auths.append(auth)

            # RFC 1869 requires a space between EHLO keyword and parameters.
            # It's actually stricter, in that only spaces are allowed between
            # parameters, but were not going to check for that here.
            # Note that the space isn't present if there are no parameters.
            match = EXTENSION_REGEX.match(line)

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


class SMTP_SSL(SMTP):
    """
    SMTP or ESMTP client over an SSL channel.

    Attributes:
        ssl_context (:class:`ssl.SSLContext`): SSL context to use to establish
            the connection with the SMTP server.

    .. seealso: :class:`SMTP`
    """
    default_port = 465

    def __init__(self, host='localhost', port=default_port, fqdn=None,
                 context=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        """
        Initializes a new :class:`SMTP_SSL` instance.

        Sets a real SSL context. If given ``context`` is None, tries to
        create a suitable context.

        Also default port in this case is *465*.

        .. seealso:: :meth:`SMTP.__init__`
        """
        super().__init__(host, port, fqdn, timeout)

        if context is None:
            # By default, this creates a :class:`ssl.SSLContext` instance with
            # purpose set to ```ssl.Purpose.SERVER_AUTH``, which is what we
            # want.
            context = ssl.create_default_context()

        self.ssl_context = context
