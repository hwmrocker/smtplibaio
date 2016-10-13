#!/usr/bin/env python
# coding: utf-8

"""
Exception classes used in smtplibaio package.
"""


class SMTPException(Exception):
    """
    Base class for all exceptions.
    """
    default_message = ""

    def __init__(self, message=None):
        """
        """
        m = self.__class__.default_message

        if message is not None:
            m = "{0} ({1})".format(m, message)

        self.message = m


class SMTPConnectError(SMTPException):
    """
    Raised when an error occurs while trying to connect to the SMTP server.
    """
    default_message = "Unable to connect to the server."


class SMTPServerDisconnectedError(SMTPException):
    """
    Raised when the connection to the SMTP server has been unexpectedly lost
    or when a command is run without a connection.
    """
    default_message = "Connection unexpectedly closed."


class SMTPResponseException(SMTPException):
    """
    Base class for all exceptions that include an SMTP error code.

    Raised when the SMTP server returns an error code.

    The error code is stored in `code`.
    The error message is stored in `message`.
    """
    def __init__(self, code, message=None):
        """
        """
        super().__init__(message)
        self.code = code


class SMTPCommandNotSupportedError(SMTPResponseException):
    """
    Raised when the server refuses a command we sent.
    """
    default_message = "Command not supported by the server."


class SMTPSenderRefusedError(SMTPResponseException):
    """
    Raised when the server refuses the sender address.

    In addition to the attributes set by on all `SMTPResponseException`,
    this sets `sender` to the string that the SMTP refused.
    """
    default_message = "Sender refused by the server."

    def __init__(self, sender, code, message=None):
        """
        """
        super().__init__(code, message)
        self.sender = sender


class SMTPRecipientRefusedError(SMTPResponseException):
    """
    Raised when the server refuses a recipient address.

    In addition to the attributes set by on all `SMTPResponseException`,
    this sets `recipient` to the string that the SMTP server refused.
    """
    default_message = "Recipient refused by the server."

    def __init__(self, recipient, code, message=None):
        """
        """
        super().__init__(code, message)
        self.recipient = recipient


class SMTPAllRecipientsRefusedError(SMTPException):
    """
    Raised when the server refuses all recipients addresses.

    Simply wraps a list of `SMTPRecipientRefusedError` exceptions.
    """
    def __init__(self, excs):
        """
        """
        self.recipients = excs


class SMTPDataRefusedError(SMTPResponseException):
    """
    Raised when the server refuses our DATA content.
    """
    default_message = "DATA refused by the server."


class SMTPHeloRefusedError(SMTPResponseException):
    """
    Raised when the server refuses our HELO/EHLO reply.
    """
    default_message = "HELO or EHLO refused by the server."


class SMTPAuthenticationError(SMTPResponseException):
    """
    Raised when the server rejects our authentication attempt.
    """
    default_message = "Authentication failed."


class SMTPResponseLineTooLongError(SMTPResponseException):
    """
    Raised when a reply sent by server exceeds the limit set.
    """
    def __init__(self):
        """
        RFC 2821 tells us this is a code 500 error.
        """
        super().__init__(500, "Server response is (way) too long.")
