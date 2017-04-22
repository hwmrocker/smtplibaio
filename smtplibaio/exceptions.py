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
          |   + SMTPNoRecipientError
          |   + SMTPCommandFailedError
          |       |
          |       + SMTPAuthenticationError
          |
          + BadImplementationError
          |
          + OSError
              |
              + ConnectionError
                  |
                  + ConnectionRefusedError
                  + ConnectionResetError

We made our best to document methods docstrings so you should be able to know
what exceptions a method can raise by reading the method docstring.

Please feel free to make a PR if we missed something.
"""


class BadImplementationError(Exception):
    """
    Trying to use STARTTLS with a connection using the regular ssl module.
    """


class SMTPException(Exception):
    """
    Base class for all exceptions related to smtplibaio.

    Attributes:
        message (str): Exception message, ideally providing help for the user.

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
    Raised when the client couldn't authenticate to the server.

    Attributes:
        exceptions (list of :obj:`SMTPAuthenticationError`): List of
            exceptions that were raised and that conducted to this exception
            being raised.

    Inherited attributes:
        message: (str): Exception message, ideally providing help for the user.
    """
    def __init__(self, excs):
        """
        Initializes a new instance of SMTPLoginError.

        Args:
            excs (list of :obj:`SMTPAuthenticationError`): List of exceptions
                that were raised and that conducted to this exceptions being
                raised.
        """
        super().__init__("Login failed:\n  {}")
        self.exceptions = excs

    def __str__(self):
        """
        """
        exceptions_str = "\n  ".join([str(e) for e in self.exceptions])

        return self.message.format(exceptions_str)


class SMTPNoRecipientError(SMTPException):
    """
    Raised when the server refuses all recipients addresses.

    Attributes:
        exceptions (list of :obj:`SMTPCommandFailedError`): List of
            exceptions that were raised, caught and that originated this
            exception.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.

    .. seealso:: :meth:`sendmail` source code.
    """
    def __init__(self, excs):
        """
        Initializes a new instance of SMTPNoRecipientError.

        Args:
            excs (list of :obj:`SMTPCommandFailedError`): List of
                exceptions that were raised, caught and that originated this
                exception.
        """
        super().__init__("Could not send e-mail:\n  {}")
        self.exceptions = excs

    def __str__(self):
        """
        """
        exceptions_str = "\n  ".join([str(e) for e in self.exceptions])

        return self.message.format(exceptions_str)


class SMTPCommandFailedError(SMTPException):
    """
    Raised when a command fails.

    Attributes:
        command (str): Command sent to the server that originated the
            exception.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.
    """
    def __init__(self, code, message=None, command=None):
        """
        Initializes a new instance of SMTPCommandFailedError.

        Args:
            code (int): Error code returned by the SMTP server.
            message (str): Exception message, ideally providing help for the
                user.
            command (str): Command sent to the server that originated the
                exception.
        """
        super().__init__(message)
        self.code = code
        self.command = command

    def __str__(self):
        """
        """
        s = "Command \"{}\" failed : [{}] {}"

        return s.format(self.command, self.code, self.message)


class SMTPAuthenticationError(SMTPCommandFailedError):
    """
    Raised when the server rejects our authentication attempt.

    Attributes:
        mechanism (str): Name of the mechanism used to authenticate.

    Inherited attributes:
        message (str): Exception message, ideally providing help for the user.
        code (int): Error code returned by the SMTP server.
        command (str): Command sent to the server that originated the
            exception.
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
