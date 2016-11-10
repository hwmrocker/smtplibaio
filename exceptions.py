#!/usr/bin/env python
# coding: utf-8

"""
Exception classes used in smtplibaio package.

The exhaustive hierarchy of exceptions that might be raised in the smtplibaio
package is as follows:

    BaseException
      |
      + Exception
          |
          + SMTPException
          |   |
          |   + SMTPLoginError
          |   + SMTPAllRecipientsRefusedError
          |   + SMTPResponseException
          |       |
          |       + SMTPSenderRefusedError
          |       + SMTPRecipientRefusedError
          |       + SMTPDataRefusedError
          |       + SMTPHelloRefusedError
          |       + SMTPAuthenticationError
          |
          + OSError
              |
              + ConnectionError
                  |
                  + ConnectionRefusedError
                  + ConnectionResetError


This hierarchy should allow you to easily catch a family of exceptions.

For exemple, you can catch ``SMTPResponseException`` instead of catching all
of the 6 inheriting classes.

We made our best to document methods docstrings so you should be able to know
what exceptions a method can raise by reading the method docstring.

Please feel free to make a PR if we missed something.
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
    def __init__(self, message=None):
        """
        Initializes a new instance of SMTPException.

        Args:
            message (str): Exception message.

        .. note:: You SHOULD NOT use this class directly. Instead, you should
            subclass it or use one of the existing subclasses provided in this
            module.
        """
        self.message = message

class SMTPLoginError(SMTPException):
    """
    Raised when the server refuses all authentication attempts.

    Attributes:
        exceptions (list of :obj:`SMTPAuthenticationError`): List of
            exceptions that were raised and that conducted to this exception
            being raised.

    Inherited attributes:
        message: (str): Exception message, ideally providing help for the user.

    Inherited class attributes:
        default_message (str): Generic exception message.
    """
    def __init__(self, excs):
        """
        Initializes a new instance of SMTPLoginError.

        Args:
            excs (list of :obj:`SMTPAuthenticationError`): List of exceptions
                that were raised and that conducted to this exceptions being
                raised.
        """
        super().__init__("Login failed: Causes are: \n  {}")
        self.exceptions = excs

    def __str__(self):
        """
        """
        exceptions_str = "\n  ".join([str(e) for e in self.exceptions])

        return self.message.format(exceptions_str)

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
        super().__init__()
        self.exceptions = excs

    def __str__(self):
        """
        """
        return "\n".join([str(e) for e in self.exceptions])

class SMTPCommandFailedError(SMTPException):
    """
    FIXME

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.

    Inherited class attributes:
        default_message (str): Generic exception message.
    """
    def __init__(self, code, message=None, command=None):
        """
        Initializes a new instance of SMTPCommandFailedError.

        Args:
            code (int): Error code returned by the SMTP server.
            message (str): Exception message, ideally providing help for the
                user.
            command (str): Command that resulted in this exception being
                raised.
        """
        super().__init__(message)
        self.code = code
        self.command = command

    def __str__(self):
        """
        """
        s = "Command \"{}\" failed : [{}] {}"

        return s.format(self.command, self.code, self.message)

class SMTPResponseException(SMTPException):
    """
    Base class for all exceptions that include an SMTP error code.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.
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
    """
    
    default_message = "DATA refused by the server."


class SMTPHelloRefusedError(SMTPResponseException):
    """
    Raised when the server refuses our HELO/EHLO greeting.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.
    """
    def __str__(self):
        """
        """
        return "HELO or EHLO 
        if self.message is None:
            self.message = "{} HELO or EHLO refused by the server

class SMTPAuthenticationError(SMTPResponseException):
    """
    Raised when the server rejects our authentication attempt.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.
        mechanism (str): Name of the mechanism used to authenticate.
   """
    def __init__(self, code, message=None, mechanism=None):
        """
        """
        super().__init__(code, message)
        self.mechanism = mechanism

    def __str__(self):
        """
        """
        s = "Authentication failed"

        if self.mechanism:
            s += " using {} mechanism".format(self.mechanism)

        s += ". [{}] {}".format(self.code, self.message)

        return s
