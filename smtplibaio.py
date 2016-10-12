#!/usr/bin/env python
# coding: utf-8

'''SMTP/ESMTP client class.

This should follow RFC 821 (SMTP), RFC 1869 (ESMTP), RFC 2554 (SMTP
Authentication) and RFC 2487 (Secure SMTP over TLS).

Notes:

Please remember, when doing ESMTP, that the names of the SMTP service
extensions are NOT the same thing as the option keywords for the RCPT
and MAIL commands!

Example:

async def send(from_email, to_email, msg)
    server = SMTP_SSL()
    code, _ = await server.connect(mail_server)
    assert code == 220, "connect failed"
    try:
        await server.login(mailbox_name, mailbox_password)
        await server.sendmail(from_email, to_email, msg.as_string())
    finally:
        await server.quit()
'''

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

from email.base64mime import body_encode as encode_base64
from sys import stderr

import threading

from smtplibaio.exceptions import (
    SMTPException,
    SMTPResponseException,
    SMTPConnectError,
    SMTPServerDisconnectedError,
    SMTPCommandNotSupportedError,
    SMTPSenderRefusedError,
    SMTPRecipientRefusedError,
    SMTPAllRecipientsRefusedError,
    SMTPDataRefusedError,
    SMTPHeloRefusedError,
    SMTPAuthenticationError
)


SMTP_PORT = 25
SMTP_SSL_PORT = 465

CRLF = "\r\n"
bCRLF = b"\r\n"

_MAXLINE = 8192  # more than 8 times larger than RFC 821, 4.5.3

OLDSTYLE_AUTH = re.compile(r"auth=(.*)", re.I)


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


# Legacy method kept for backward compatibility.
def quotedata(data):
    """Quote data for email.

    Double leading '.', and change Unix newline '\\n', or Mac '\\r' into
    Internet CRLF end-of-line.
    """
    return re.sub(r'(?m)^\.',
                  '..',
                  re.sub(r'(?:\r\n|\n|\r(?!\n))',
                         CRLF,
                         data))


def _quote_periods(bindata):
    return re.sub(br'(?m)^\.', b'..', bindata)


def _fix_eols(data):
    return re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data)

try:
    import ssl
except ImportError:
    _have_ssl = False
else:
    _have_ssl = True


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

    def __init__(self, hostname='localhost', port=_default_port,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None,
                 loop=None):
        """
        Initializes a new instance.

        FIXME: rewrite docstring

        If specified, `host' is the name of the remote host to which to
        connect.  If specified, `port' specifies the port to which to connect.
        By default, smtplibaio.SMTP_PORT is used.

        If a host is specified the connect method is called, and if it returns
        anything other than a success code an SMTPConnectError is raised.
 
        The `source_address` parameter takes a 2-tuple (host,
        port) for the socket to bind to as its source address before
        connecting.
        """
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.source_address = source_address

        self.last_helo_response = (None, None)
        self.last_ehlo_response = (None, None)
        
        self.supports_esmtp = False
        self.esmtp_extensions = {}

        self.reader = None
        self.writer = None

        self.loop = loop or asyncio.get_event_loop()

        # self.helo_resp = None
        # self.ehlo_msg = "ehlo"
        # self.ehlo_resp = None
        # self.does_esmtp = False

        # self.esmtp_features = {}
        # self.source_address = source_address

        # self._loop = loop if loop else asyncio.get_event_loop()

        # self._reader = None
        # self._writer = None

        # self._set_host_and_port(host, port) \
        #     ._set_local_hostname(local_hostname)

    @classmethod
    def set_debuglevel(cls, debuglevel):
        """
        Set the debug output level.
        """
        cls.debug_level = debuglevel

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

        .. _`asyncio Streams`: https://docs.python.org/3/library/asyncio-stream.html
        """
        if self.__class__.debug_level > 0:
            print("Connect: {0}"
                  .format((self.host, self.port)),
                  file=stderr)

        connect = asyncio.open_connection(self.hostname,
                                          self.port,
                                          ssl=False,
                                          local_addr=self.source_address,
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

    async def send(self, s):
        """
        Sends the given string to the server.
        """
        if self.__class__.debug_level > 0:
            print("Send: {0}".format(repr(s)), file=stderr)

        # Check if we have a writer
        # (should be the case if we are connected):
        if self.writer is None:
            self.close()
            raise SMTPServerDisconnectedError()
        else:
            if isinstance(s, str):
                s = s.encode("ascii")

            # Don't try/except here since this will "mask" the
            # GeneratorExit Exception that has to be raised.
            self.writer.write(s)
            await self._writer.drain()

    async def put_cmd(self, cmd, args=None):
        """
        Sends a command to the server.
        """
        if args is None:
            str = '%s%s' % (cmd, CRLF)
        else:
            str = '%s %s%s' % (cmd, args, CRLF)

        try:
            await self.send(str)
        except OSError as e:
            self.close()
            raise SMTPServerDisconnectedError(e)

    async def get_reply(self):
        """
        Gets a reply from the server.

        Returns a tuple consisting of:

          - server response code (e.g. '250', or such, if all goes well)
            Note: returns -1 if it can't read response code.

          - server response string corresponding to response code (multiline
            responses are converted to a single, multiline string).

        Raises SMTPServerDisconnected if end-of-file is reached.
        """
        errcode = -1
        resp = []

        go_on = True

        while go_on:
            try:
                line = await self.reader.readline()
            except OSError as e:
                self.close()
                raise SMTPServerDisconnectedError(e)
                
            if not line:
                self.close()
                raise SMTPServerDisconnectedError()

            if len(line) > _MAXLINE:
                self.close()
                # FIXME: we should not instanciate SMTPResponseException directly.
                raise SMTPResponseException(500, "Line too long.")

            msg = line[4:].strip(b' \t\r\n')

            resp.append(msg)
            code = line[:3]

            # Check that the error code is syntactically correct.
            # Don't attempt to read a continuation line if it is broken.
            try:
                errcode = int(code)
            except ValueError:
                errcode = -1
                go_on = False
            else:
                # Check if we have a multiline response:
                go_on = (line[3:4] == b'-')

            if self.__class__.debug_level > 0:
                print("Reply: code: {0}, msg: {1}"
                      .format(errcode, msg),
                      file=stderr)

        errmsg = b"\n".join(resp)

        return errcode, errmsg

    async def do_cmd(self, cmd, args=""):
        """
        Sends the given command to the server.

        Returns a tuple containing the response code and message.
        """
        await self.put_cmd(cmd, args)

        return await self.get_reply()

    async def helo(self, name=''):
        """SMTP 'helo' command.
        Hostname to send for this command defaults to the FQDN of the local
        host.
        """
        await self.put_cmd("helo", name or self.local_hostname)
        code, message = await self.get_reply()
        self.last_helo_response = (code, message)

        if self.__class__.debug_level > 0:
            print("HELO command: {0} {1}".format(code, message))

        return code, message

    async def ehlo(self, name=''):
        """ SMTP 'ehlo' command.
        Hostname to send for this command defaults to the FQDN of the local
        host.
        """
        await self.put_cmd(self.ehlo_msg, name or self.local_hostname)
        code, message = await self.get_reply()
        self.last_ehlo_response = (code, message)

        # According to RFC1869 some (badly written)
        # MTA's will disconnect on an ehlo. Toss an exception if
        # that happens -ddm
        if code == -1 and len(msg) == 0:
            self.close()
            raise SMTPServerDisconnectedError()

        if code != 250:
            return (code, msg)

        self.does_esmtp = 1

        # parse the ehlo response -ddm
        assert isinstance(self.ehlo_resp, bytes), repr(self.ehlo_resp)
        resp = self.ehlo_resp.decode("latin-1").split('\n')
        # del resp[0]

        for each in resp[1:]:
            # To be able to communicate with as many SMTP servers as possible,
            # we have to take the old-style auth advertisement into account,
            # because:
            # 1) Else our SMTP feature parser gets confused.
            # 2) There are some servers that only advertise the auth methods we
            #    support using the old style.
            auth_match = OLDSTYLE_AUTH.match(each)

            if auth_match:
                # This doesn't remove duplicates, but that's no problem
                self.esmtp_features["auth"] = self.esmtp_features.get("auth", "") \
                        + " " + auth_match.groups(0)[0]
                continue

            # RFC 1869 requires a space between ehlo keyword and parameters.
            # It's actually stricter, in that only spaces are allowed between
            # parameters, but were not going to check for that here.  Note
            # that the space isn't present if there are no parameters.
            m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*) ?', each)
            if m:
                feature = m.group("feature").lower()
                params = m.string[m.end("feature"):].strip()
                if feature == "auth":
                    self.esmtp_features[feature] = self.esmtp_features.get(feature, "") \
                            + " " + params
                else:
                    self.esmtp_features[feature] = params
        return (code, msg)

    def has_extn(self, opt):
        """
        Returns True if the server supports the given SMTP service extension.
        """
        return opt.lower() in self.esmtp_features

    async def help(self, args=''):
        """SMTP 'help' command.
        Returns help text from server."""
        await self.put_cmd("help", args)

        return (await self.get_reply()[1])

    async def rset(self):
        """SMTP 'rset' command -- resets session."""
        return (await self.do_cmd("rset"))

    async def _rset(self):
        """Internal 'rset' command which ignores any SMTPServerDisconnected error.

        Used internally in the library, since the server disconnected error
        should appear to the application when the *next* command is issued, if
        we are doing an internal "safety" reset.
        """
        try:
            await self.rset()
        except SMTPServerDisconnected:
            pass

    async def noop(self):
        """SMTP 'noop' command -- doesn't do anything :>"""
        return (await self.do_cmd("noop"))

    async def mail(self, sender, options=[]):
        """SMTP 'mail' command -- begins mail xfer session."""
        optionlist = ''

        if options and self.does_esmtp:
            optionlist = ' ' + ' '.join(options)

        await self.put_cmd("mail", "FROM:%s%s" % (quoteaddr(sender), optionlist))

        return (await self.get_reply())

    async def rcpt(self, recip, options=[]):
        """SMTP 'rcpt' command -- indicates 1 recipient for this mail."""
        optionlist = ''

        if options and self.does_esmtp:
            optionlist = ' ' + ' '.join(options)

        await self.put_cmd("rcpt", "TO:%s%s" % (quoteaddr(recip), optionlist))

        return (await self.get_reply())

    async def data(self, msg):
        """SMTP 'DATA' command -- sends message data to server.

        Automatically quotes lines beginning with a period per rfc821.
        Raises SMTPDataError if there is an unexpected reply to the
        DATA command; the return value from this method is the final
        response code received when the all data is sent.  If msg
        is a string, lone '\\r' and '\\n' characters are converted to
        '\\r\\n' characters.  If msg is bytes, it is transmitted as is.
        """
        await self.put_cmd("data")
        code, repl = await self.get_reply()

        if self.__class__.debug_level > 0:
            print("data:", (code, repl), file=stderr)

        if code != 354:
            raise SMTPDataRefusedError(code, repl)
        else:
            if isinstance(msg, str):
                msg = _fix_eols(msg).encode('ascii')
            q = _quote_periods(msg)

            if q[-2:] != bCRLF:
                q = q + bCRLF
            q = q + b"." + bCRLF

            await self.send(q)
            code, msg = await self.get_reply()

            if self.__class__.debug_level > 0:
                print("data:", (code, msg), file=stderr)

            return (code, msg)

    async def verify(self, address):
        """SMTP 'verify' command -- checks for address validity."""
        await self.put_cmd("vrfy", _addr_only(address))
        return (await self.get_reply())
    # a.k.a.
    vrfy = verify

    async def expn(self, address):
        """SMTP 'expn' command -- expands a mailing list."""
        await self.put_cmd("expn", _addr_only(address))

        return (await self.get_reply())

    # some useful methods

    async def ehlo_or_helo_if_needed(self):
        """Call self.ehlo() and/or self.helo() if needed.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        This method may raise the following exceptions:

         SMTPHeloError            The server didn't reply properly to
                                  the helo greeting.
        """
        if self.helo_resp is None and self.ehlo_resp is None:
            tmp, _ = await self.ehlo()
            if not (200 <= tmp <= 299):
                (code, resp) = await self.helo()
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)

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

        if not self.has_extn("auth"):
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

        if not self.has_extn("starttls"):
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
            msg = _fix_eols(msg).encode('ascii')

        if self.does_esmtp:
            # Hmmm? what's this? -ddm
            # self.esmtp_features['7bit']=""
            if self.has_extn('size'):
                esmtp_opts.append("size=%d" % len(msg))

            esmtp_opts.extend(mail_options)

        code, resp = await self.mail(from_addr, esmtp_opts)

        if code != 250:
            if code == 421:
                self.close()
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

    def close(self):
        """
        Cleans up after the connection to the SMTP server
        has been closed voluntarily or not).
        
        Resets `_writer`, `ehlo_resp`, `helo_resp`, `esmtp_features`
        and `does_smtp`.
        """
        self.is_connected = False

        if self._writer is not None:
            self._writer.close()

        self._writer = None
        self.ehlo_resp = self.helo_resp = None
        self.esmtp_features = {}
        self.does_esmtp = False

    async def quit(self):
        """
        Terminates the SMTP session.

        Raises SMTPServerDisconnected if the connection is already closed.
        Raises SMTPResponseException if something wrong happens.
        """
        try:
            code, message = await self.do_cmd("quit")
        except SMTPServerDisconnectedError as e:
            raise e
        except SMTPResponseException as e:
            raise e
        else:
            if code != 221:
                raise SMTPResponseException(code, message)
        finally:
            self.close

        return (code, message)

if _have_ssl:

    class SMTP_SSL(SMTP):
        """ This is a subclass derived from SMTP that connects over an SSL
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

        default_port = SMTP_SSL_PORT

        def __init__(self, host='', port=0, local_hostname=None,
                     keyfile=None, certfile=None,
                     timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                     source_address=None, context=None):
            """
            Initializes a new SMTP_SSL instance.

            Raises ValueError in the following cases:

            * Both `context` and `keyfile` have been given ;
            * Both `context` and `certfile` have been given.
            """
            if context is not None and keyfile is not None:
                raise ValueError("context and keyfile arguments are mutually "
                                 "exclusive")

            if context is not None and certfile is not None:
                raise ValueError("context and certfile arguments are mutually "
                                 "exclusive")

            self.keyfile = keyfile
            self.certfile = certfile

            if context is None:
                context = ssl._create_stdlib_context(certfile=certfile,
                                                     keyfile=keyfile)

            self.context = context

            super().__init__(self, host, port, local_hostname, timeout,
                             source_address)

        def _get_socket(self, host, port, timeout):
            """
            """
            if self.__class__.debug_level > 0:
                print('connect:', (host, port), file=stderr)

            new_socket = socket.create_connection((host, port),
                                                  timeout,
                                                  self.source_address)
            new_socket = self.context.wrap_socket(new_socket, server_hostname=host)

            return new_socket

    __all__.append("SMTP_SSL")


# Test the sendmail method, which tests most of the others.
# Note: This always sends to localhost.
if __name__ == '__main__':
    print("test need to written for asyncio")
    import sys
    sys.exit(0)

    def prompt(prompt):
        sys.stdout.write(prompt + ": ")
        sys.stdout.flush()
        return sys.stdin.readline().strip()

    fromaddr = prompt("From")
    toaddrs = prompt("To").split(',')
    print("Enter message, end with ^D:")
    msg = ''
    while 1:
        line = sys.stdin.readline()
        if not line:
            break
        msg = msg + line
    print("Message length is %d" % len(msg))

    server = SMTP('localhost')
    server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddrs, msg)
    server.quit()
