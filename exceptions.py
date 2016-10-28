#!/usr/bin/env python
# coding: utf-8

"""
Exception classes used in smtplibaio package.
"""


class SMTPException(Exception):
    """
    Base class for all exceptions related to smtplibaio.

    Attributes:
        message (str): Exception message, ideally providing help for the user.

    Class attributes:
        default_message (str): Generic exception message.

    .. note:: You SHOULD NOT use this class directly. Instead, you should
        subclass it or use one of the existing subclasses provided in this
        module.
    """
    default_message = ""

    def __init__(self, message=None):
        """
        Initializes a new instance of SMTPException.

        If ``message`` is given (not *None*), it is appended to the subclass
        ``default_message`.
        The ``default_message`` should give a general clue about what's
        going on.
        The ``message`` should give more details about the exception.

        .. note:: You SHOULD NOT use this class directly. Instead, you should
            subclass it or use one of the existing subclasses provided in this
            module.
        """
        m = self.__class__.default_message

        if message is not None:
            m = "{0} ({1})".format(m, message)

        self.message = m

    def __str__(self):
        """
        """
        return self.message

class SMTPAllRecipientsRefusedError(SMTPException):
    """
    Raised when the server refuses all recipients addresses.

    Attributes:
        exceptions (list of :obj:`SMTPRecipientRefusedError`): List of
            exceptions that were raised and that conducted to this exception
            being raised.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.

    Inherited class attributes:
        default_message (str): Generic exception message.

    .. seealso:: :meth:`sendmail` source code.
    """
    def __init__(self, excs):
        """
        Initializes a new instance of SMTPAllRecipientsRefusedError.

        Args:
            excs (list of :obj:`SMTPRecipientRefusedError`): List of
                exceptions that were raised and that conducted to this
                exception being raised.
        """
        self.exceptions = excs

    def __str__(self):
        """
        """
        return "\n".join(self.exceptions)

class SMTPResponseException(SMTPException):
    """
    Base class for all exceptions that include an SMTP error code.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
    """
    def __init__(self, code, message=None):
        """
        Initializes a new instance of SMTPReponseException.

        Args:
            code (int): Error code returned by the SMTP server.
            message (str): Exception message, ideally providing help for the
                user.
        """
        super().__init__(message)
        self.code = code

    def __str__(self):
        """
        """
        return "{} (Returned code was: {})".format(self.message, self.code)

class SMTPCommandNotSupportedError(SMTPResponseException):
    """
    Raised when the server refuses a command we sent.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
    """
    default_message = "Command not supported by the server."


class SMTPSenderRefusedError(SMTPResponseException):
    """
    Raised when the server refuses the sender address.

    Attributes:
        sender (str): Sender address that is refused.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
    """
    default_message = "Sender refused by the server."

    def __init__(self, sender, code, message=None):
        """
        Initializes a new instance of SMTPSenderRefusedError.

        Args:
            sender (str): Sender e-mail address that was refused.
            code (int): Error code returned by the SMTP server.
            message (str): Exception message, ideally providing help for the
                user.
        """
        super().__init__(code, message)
        self.sender = sender

    def __str__(self):
        """
        """
        return "Sender <{}>: {}".format(self.sender, self.message)

class SMTPRecipientRefusedError(SMTPResponseException):
    """
    Raised when the server refuses a recipient address.

    Attributes:
        recipient (str): Recipient address that is refused.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
    """
    default_message = "Recipient refused by the server."

    def __init__(self, recipient, code, message=None):
        """
        Initializes a new instance of SMTPRecipientRefusedError.

        Args:
            recipient (str): Recipient e-mail address that was refused.
            code (int): Error code returned by the SMTP server.
            message (str): Exception message, ideally providing help for the
                user.

        """
        super().__init__(code, message)
        self.recipient = recipient

    def __str__(self):
        """
        """
        return "Recipient <{}>: {}".format(self.recipient, self.message)

class SMTPDataRefusedError(SMTPResponseException):
    """
    Raised when the server refuses our DATA content.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
   """
    default_message = "DATA refused by the server."


class SMTPHelloRefusedError(SMTPResponseException):
    """
    Raised when the server refuses our HELO/EHLO greeting.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
   """
    default_message = "HELO or EHLO refused by the server."


class SMTPAuthenticationError(SMTPResponseException):
    """
    Raised when the server rejects our authentication attempt.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
   """
    default_message = "Authentication failed."
