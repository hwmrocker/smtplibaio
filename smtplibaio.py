#!/usr/bin/env python
# coding: utf-8

"""
SMTP/ESMTP client class.

This should follow RFC 2821 (SMTP), RFC 1869 (ESMTP), RFC 2554 (SMTP
Authentication) and RFC 2487 (Secure SMTP over TLS).

Example:

    async def sendSSL(from_addr, to_addr, msg, mailbox_name, mailbox_pwd):
        try:
            async with SMTP_SSL() as server:
                server.login(mailbox_name, mailbox_pwd)
                server.sendmail(from_addr, to_addr, msg.as_string())
        except SMTPConnectError as e:
            print(e, file=sys.stderr)

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
    SMTPConnectError,
    SMTPServerDisconnectedError,
    SMTPCommandNotSupportedError,
    SMTPSenderRefusedError,
    SMTPRecipientRefusedError,
    SMTPAllRecipientsRefusedError,
    SMTPDataRefusedError,
    SMTPHeloRefusedError,
    SMTPAuthenticationError,
    SMTPResponseLineTooLongError,
)
from streams import SMTPStreamReader, SMTPStreamWriter


SMTP_PORT = 25
SMTP_SSL_PORT = 465

CRLF = "\r\n"
bCRLF = b"\r\n"

_MAXLINE = 8192  # more than 8 times larger than RFC 821, 4.5.3

OLDSTYLE_AUTH_REGEX = re.compile(r"auth=(?P<auth>.*)", re.IGNORECASE)
EXTENSION_REGEX = re.compile(r"(?P<feature>[a-z0-9][a-z0-9\-]*) ?", re.IGNORECASE)


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
    # FIXME: rewrite docstring
    """
    This class manages a connection to an SMTP or ESMTP server.
    SMTP Objects:
        SMTP objects have the following attributes:
            helo_resp
                This is the message given by the server in response to the
                most recent HELO command.

            ehlo_resp
                This is the message given by the server in response to the
                most recent EHLO command. This is usually multiline.

            does_esmtp
                This is a True value _after you do an EHLO command_, if the
                server supports ESMTP.

            esmtp_features
                This is a dictionary, which, if the server supports ESMTP,
                will _after you do an EHLO command_, contain the names of the
                SMTP service extensions this server supports, and their
                parameters (if any).

                Note, all extension names are mapped to lower case in the
                dictionary.

        See each method's docstrings for details.  In general, there is a
        method of the same name to perform each SMTP command.  There is also a
        method called 'sendmail' that will do an entire mail transaction.
        """
    _default_port = SMTP_PORT
    debug_level = 0

    def __init__(self, hostname='localhost', port=_default_port, fqdn=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT, loop=None):
        """
        Initializes a new instance.

        FIXME: rewrite docstring

        If specified, `host' is the name of the remote host to which to
        connect.  If specified, `port' specifies the port to which to connect.
        By default, smtplibaio.SMTP_PORT is used.

        If a host is specified the connect method is called, and if it returns
        anything other than a success code an SMTPConnectError is raised.
        """
        self.hostname = hostname

        try:
            self.port = int(port)
        except ValueError:
            self.port = self.__class__._default_port

        self.timeout = timeout
        self._fqdn = fqdn

        self.reset_state()

        self.loop = loop or asyncio.get_event_loop()

    @property
    def fqdn(self):
        """
        Returns the string used to identify the client when initiating a SMTP
        session.

        RFC 2821 tells us what to do:

        * Use the client FQDN ;
        * If it isn't available, we SHOULD fall back to an address literal.
        """
        if self._fqdn is None:
            # Let's try to retrieve it:
            self._fqdn = socket.getfqdn()

            if '.' not in self._fqdn:
                # FQDN doesn't seem to be valid, fall back to address literal,
                # See RFC 2821 § 4.1.1.1 and § 4.1.3
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

        This is especially useful when initializing a newly created SMTP
        instance and when closing an existing SMTP session.

        It allows us to use the same SMTP instance and connect several times.
        """
        self.last_helo_response = (None, None)
        self.last_ehlo_response = (None, None)

        self.supports_esmtp = False
        self.esmtp_extensions = {}

        self.auth_methods = []

        self.reader = None
        self.writer = None
        self.transport = None

    async def __aenter__(self):
        """
        Enters the asynchronous context manager.

        Also tries to connect to the server.
        """
        await self.connect()

        return self

    async def __aexit__(self, *args):
        """
        Exits the asynchronous context manager.

        See :py:func:`quit` for further details.
        """
        await self.quit()

    async def connect(self):
        """
        Connects to the server.

        We use `asyncio Streams`_.

        Note: This method is automatically invoked by `__aenter__`.
              Mostly borrowed from asyncio.streams.open_connection(...)
              source code.

        .. _`asyncio Streams`: https://docs.python.org/3/library/asyncio-stream.html
        """
        if self.__class__.debug_level > 0:
            print("Connect: {0}"
                  .format((self.hostname, self.port)),
                  file=stderr)

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
            'ssl': False
        }

        try:
            self.transport, _ = await self.loop.create_connection(**conn)
        except OSError as e:
            # FIXME: we need a code here !
            raise SMTPConnectError(e)

        # If the connection has been established, build the writer:
        self.writer = SMTPStreamWriter(self.transport, protocol, self.reader,
                                       self.loop)

        try:
            code, message = await self.reader.read_reply()
        except SMTPResponseLineTooLongError as e:
            raise SMTPConnectError(e.code, e.message)

        if self.__class__.debug_level > 0:
            print("Reply: code: {} - msg: {}".format(code, message),
                  file=stderr)

        if code != 220:
            raise SMTPConnectError(code, message)

    async def do_cmd(self, *args):
        """
        Sends the given command to the server.

        Returns a (code, message) tuple containing the server response.
        """
        # FIXME: should we do some check before ?
        if self.__class__.debug_level > 0:
            print("Send: {0}".format(" ".join(args)), file=stderr)

        await self.writer.send_command(*args)

        try:
            code, message = await self.reader.read_reply()
        except SMTPResponseLineTooLongError as e:
            raise e

        if self.__class__.debug_level > 0:
            print("Reply: code: {} - msg: {}".format(code, message),
                  file=stderr)

        return code, message

    async def helo(self, from_host=None):
        """
        Sends a SMTP 'HELO' command. - Identifies the client and starts the
        session.

        If given `from_host` is None, defaults to FQDN.

        Raises SMTPHeloRefusedError when the server refuses the connection.

        Returns a (code, message) tuple containing the server response.
        """
        if from_host is None:
            from_host = self.fqdn

        code, message = await self.do_cmd('HELO', from_host)
        self.last_helo_response = (code, message)

        if code != 250:
            raise SMTPHeloRefusedError(code, message)

        return code, message

    async def ehlo(self, from_host=None):
        """
        Sends a SMTP 'EHLO' command. - Identifies the client and starts the
        session.

        If given `from_host` is None, defaults to FQDN.

        Raises SMTPHeloRefusedError when the server refuses the connection.

        Returns a (code, message) tuple containing the server response.
        """
        if from_host is None:
            from_host = self.fqdn

        code, message = await self.do_cmd('EHLO', from_host)
        self.last_ehlo_response = (code, message)

        if code != 250:
            raise SMTPHeloRefusedError(code, message)

        extns, auths = SMTP.parse_esmtp_extensions(message)
        self.esmtp_extensions = extns
        self.auth_methods = auths
        self.supports_esmtp = True

        return code, message

    async def help(self, args=''):
        """
        Sends a SMTP 'HELP' command.

        Returns help text as given by the server.
        """
        code, message = await self.do_cmd('HELP', args)

        return message

    async def rset(self):
        """
        Sends a SMTP 'RSET' command. - Resets the session.

        Returns a (code, message) tuple containing the server response.
        """
        return await self.do_cmd('RSET')

    async def _rset(self):
        """
        # FIXME: most probably to be removed.

        Internal 'RSET' command which ignores any SMTPServerDisconnected error.

        Used internally in the library, since the server disconnected error
        should appear to the application when the *next* command is issued, if
        we are doing an internal "safety" reset.
        """
        try:
            await self.rset()
        except SMTPServerDisconnected:
            pass

    async def noop(self):
        """
        Sends a SMTP 'NOOP' command. - Doesn't do anything.

        Returns a (code, message) tuple containing the server response.
        """
        return await self.do_cmd('NOOP')

    async def vrfy(self, address):
        """
        Sends a SMTP 'VRFY' command. - Tests the validity of the given address.

        Returns a (code, message) tuple containing the server response.
        """
        return await self.do_cmd('VRFY', _addr_only(address))

    async def expn(self, address):
        """
        Sends a SMTP 'EXPN' command. - Expands a mailing-list.

        Returns a (code, message) tuple containing the server response.
        """
        return await self.do_cmd('EXPN', _addr_only(address))

    async def mail(self, sender, options=None):
        """
        Send a SMTP 'MAIL' command. - Starts the mail transfer session.

        Returns a (code, message) tuple containing the server response.

        # FIXME: we should probably raise a SMTPSenderRefusedError in some
                 cases.
        """
        if options is None:
            options = []

        from_addr = "FROM:{}".format(quoteaddr(sender))

        code, message = await self.do_cmd('MAIL', from_addr, *options)

        return code, message

    async def rcpt(self, recipient, options=None):
        """
        Sends a SMTP 'RCPT' command. - Indicates a recipient for the e-mail.

        Returns a (code, message) tuple containing the server response.

        # FIXME: we should probably raise a SMTPRecipientRefusedError in some
                 cases.
        """
        if options is None:
            options = []

        to_addr = "TO:{}".format(quoteaddr(recipient))

        code, message = await self.do_cmd('RCPT', to_addr, *options)

        return code, message

    async def quit(self):
        """
        Sends a SMTP 'QUIT' command. - Ends the session.

        Returns a (code, message) tuple containing the server response.

        # FIXME: should we explicitly ignore Exceptions to make sure
        `close` is called ?
        """
        code, message = await self.do_cmd('QUIT')
        await self.close()

        return code, message

    async def data(self, email_message):
        """
        Sends a SMTP 'DATA' command. - Transmits the message to the server.

        Automatically quotes lines beginning with a period (RFC 821).

        If `data` is a str object, converts lone '\\r' and '\\n' to '\\r\\n'.
        If `data` is a bytes object, sends it as is.

        Raises SMTPDataRefusedError when the server replies with something
        unexpected.

        Returns a (code, message) tuple containing the last server response
        (the one it sent after all data were sent by the client).
        """
        code, message = await self.do_cmd('DATA')

        if self.__class__.debug_level > 0:
            print("DATA: {} {}".format(code, message), file=stderr)

        if code != 354:
            raise SMTPDataRefusedError(code, message)

        email_message = SMTP.prepare_message(email_message)

        self.writer.write(email_message)    # write is non-blocking
        await self.writer.drain()
        code, message = await self.reader.read_reply()

        if self.__class__.debug_level > 0:
            print("DATA: {} {}".format(code, message), file=stderr)

        return code, message

    async def login(self, user, password):
        """Log in on an SMTP server that requires authentication.

        The arguments are:
            - user:     The user name to authenticate with.
            - password: The password for the authentication.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        This method will return normally if the authentication was successful.

        This method may raise the following exceptions:

         SMTPHeloError            The server didn't reply properly to
                                  the helo greeting.
         SMTPAuthenticationError  The server didn't accept the username/
                                  password combination.
         SMTPException            No suitable authentication method was
                                  found.
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

    async def sendmail(self, from_addr, to_addrs, msg, mail_options=[],
                 rcpt_options=[]):
        """This command performs an entire mail transaction.

        The arguments are:
            - from_addr    : The address sending this mail.
            - to_addrs     : A list of addresses to send this mail to.  A bare
                             string will be treated as a list with 1 address.
            - msg          : The message to send.
            - mail_options : List of ESMTP options (such as 8bitmime) for the
                             mail command.
            - rcpt_options : List of ESMTP options (such as DSN commands) for
                             all the rcpt commands.

        msg may be a string containing characters in the ASCII range, or a byte
        string.  A string is encoded to bytes using the ascii codec, and lone
        \\r and \\n characters are converted to \\r\\n characters.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.  If the server does ESMTP, message size
        and each of the specified options will be passed to it.  If EHLO
        fails, HELO will be tried and ESMTP options suppressed.

        This method will return normally if the mail is accepted for at least
        one recipient.  It returns a dictionary, with one entry for each
        recipient that was refused.  Each entry contains a tuple of the SMTP
        error code and the accompanying error message sent by the server.

        This method may raise the following exceptions:

         SMTPHeloError          The server didn't reply properly to
                                the helo greeting.
         SMTPRecipientsRefused  The server rejected ALL recipients
                                (no mail was sent).
         SMTPSenderRefused      The server didn't accept the from_addr.
         SMTPDataError          The server replied with an unexpected
                                error code (other than a refusal of
                                a recipient).

        Note: the connection will be open even after an exception is raised.

        Example:

         >>> import smtplib
         >>> s=smtplib.SMTP("localhost")
         >>> tolist=["one@one.org","two@two.org","three@three.org","four@four.org"]
         >>> msg = '''\\
         ... From: Me@my.org
         ... Subject: testin'...
         ...
         ... This is a test '''
         >>> s.sendmail("me@my.org",tolist,msg)
         { "three@three.org" : ( 550 ,"User unknown" ) }
         >>> s.quit()

        In the above example, the message was accepted for delivery to three
        of the four addresses, and one was rejected, with the error code
        550.  If all addresses are accepted, then the method will return an
        empty dictionary.

        """
        await self.ehlo_or_helo_if_needed()

        esmtp_opts = []

        if isinstance(msg, str):
            msg = SMTP.prepare_message(msg)

        if self.supports_esmtp:
            if "size" in self.esmtp_extensions:
                esmtp_opts.append("size=%d" % len(msg))

            esmtp_opts.extend(mail_options)

        code, resp = await self.mail(from_addr, esmtp_opts)

        if code != 250:
            if code == 421:
                await self.close()
            else:
                await self._rset()

            raise SMTPSenderRefusedError(from_addr, code, resp)

        senderrs = {}

        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]

        for each in to_addrs:
            code, resp = await self.rcpt(each, rcpt_options)

            if (code != 250) and (code != 251):
                senderrs[each] = (code, resp)

            if code == 421:
                self.close()
                raise SMTPAllRecipientsRefusedError(senderrs)

        if len(senderrs) == len(to_addrs):
            # the server refused all our recipients
            await self._rset()
            raise SMTPAllRecipientsRefusedError(senderrs)

        code, resp = await self.data(msg)

        if code != 250:
            if code == 421:
                self.close()
            else:
                await self._rset()

            raise SMTPDataRefusedError(code, resp)

        # if we got here then somebody got our mail
        return senderrs

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
        Calls `ehlo()` and/or `helo()` if needed.

        If there hasn't been any previous EHLO or HELO command this session,
        tries to initiate the session. ESMTP EHLO is tried first.

        Raises SMTPHeloRefusedError when the server doesn't reply properly to
        neither of EHLO and HELO commands.
        """
        no_helo = self.last_helo_response == (None, None)
        no_ehlo = self.last_ehlo_response == (None, None)

        if no_helo and no_ehlo:
            try:
                # First we try EHLO:
                await self.ehlo()
            except SMTPHeloRefusedError:
                # EHLO failed, let's try HELO:
                await self.helo()

    async def close(self):
        """
        Cleans up after the connection to the SMTP server has been closed
        (voluntarily or not).
        """
        if self.writer is not None:
            self.writer.close()

        self.reset_state()

    @classmethod
    def set_debuglevel(cls, debuglevel):
        """
        Set the debug output level.
        """
        cls.debug_level = debuglevel

    @staticmethod
    def parse_esmtp_extensions(message):
        """
        """
        extns = {}
        auths = []

        lines = message.splitlines()

        for line in lines[1:]:
            # To be able to communicate with as many SMTP servers as possible,
            # we have to take the old-style auth advertisement into account,
            # because:
            # 1. Else our SMTP feature parser gets confused.
            # 2. There are some servers that only advertise the auth methods we
            #    support using the old style.
            match = OLDSTYLE_AUTH_REGEX.match(line)

            if match:
                auth = match.group('auth')[0]
                auth = auth.lower().strip()

                if auth not in auths:
                    auths.append(auth)

            # RFC 1869 requires a space between ehlo keyword and parameters.
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

        See RFC 2821 § 4.1.1.4 and § 4.5.2 for further details.
        """
        if isinstance(message, bytes):
            bytes_message = message
        else:
            bytes_message = message.encode('ascii')

        # The original algorithm uses regexes to do this stuff.
        # This one is -IMHO- more pythonic and it is slightly faster.
        #
        # Another version is even faster, but I chose to keep something
        # more pythonic and readable.
        # FYI, the fastest way to do all this stuff seems to be
        # (according to my benchmarks):
        #
        # bytes_message.replace(b'\r\n', b'\n') \
        #              .replace(b'\r', b'\n') \
        #              .replace(b'\n', b'\r\n')
        #
        # DOT_LINE_REGEX = re.compile(rb'^\.', re.MULTILINE)
        # bytes_message = DOT_LINE_REGEX.sub(b'..', bytes_message)
        #
        # if not bytes_message.endswith(b'\r\n'):
        #     bytes_message += b'\r\n'
        #
        # bytes_message += b'\r\n.\r\n'

        lines = []

        for line in bytes_message.splitlines():
            if line.startswith(b'.'):
                line = line.replace(b'.', b'..', 1)

            lines.append(line)

        # Recompose the message with <CRLF> only:
        bytes_message = b'\r\n'.join(lines)

        # Make sure message ends with <CRLF>.<CRLF>:
        bytes_message += b'\r\n.\r\n'

        return bytes_message


class SMTP_SSL(SMTP):
    """
    This is a subclass derived from SMTP that connects over an SSL
    encrypted socket (to use this class you need a socket module that was
    compiled with SSL support). If host is not specified, '' (the local
    host) is used. If port is omitted, the standard SMTP-over-SSL port
    (465) is used.  local_hostname and source_address have the same meaning
    as they do in the SMTP class.  keyfile and certfile are also optional -
    they can contain a PEM formatted private key and certificate chain file
    for the SSL connection. context also optional, can contain a
    SSLContext, and is an alternative to keyfile and certfile; If it is
    specified both keyfile and certfile must be None.
    """
    _default_port = SMTP_SSL_PORT

    def __init__(self, host='localhost', port=_default_port, fqdn=None,
                 context=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        """
        Initializes a new SMTP_SSL instance.
        """
        if context is None:
            context = ssl.create_default_context(purpose=Purpose.SERVER_AUTH)

        self.context = context

        super().__init__(self, host, port, fqdn, timeout)

    async def connect(self):
        """
        Connects to the server.

        We use `asyncio Streams`_.

        Note: This method is automatically invoked by `__aenter__`.

        .. _`asyncio Streams`: https://docs.python.org/3/library/asyncio-stream.html
        """
        if self.__class__.debug_level > 0:
            print("Connect: {0}"
                  .format((self.hostname, self.port)),
                  file=stderr)

        connect = asyncio.open_connection(host=self.hostname,
                                          port=self.port,
                                          ssl=self.context,
                                          loop=self.loop)

        try:
            self.reader, self.writer = await connect
        except socket.gaierror as e:
            raise SMTPConnectError(e.errno, e.strerror)

        code, msg = await self.get_reply()

        if self.__class__.debug_level > 0:
            print("Connect: {0} {1}"
                  .format(code, msg),
                  file=stderr)

        if code != 220:
            raise SMTPConnectError(code, msg)
