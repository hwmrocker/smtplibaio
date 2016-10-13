#!/usr/bin/env python
# coding: utf-8


from asyncio import StreamReader, StreamWriter

from exceptions import (
    SMTPServerDisconnectedError,
    SMTPResponseLineTooLongError
)


class SMTPStreamReader(StreamReader):
    """
    """
    # RFC 2821 § 4.5.3.1 says a line is max. 512 chars long.
    # We chose to support a bit more :o)
    line_max_length = 8192

    def __init__(self, limit=line_max_length, loop=None):
        """
        Initializes a new SMTPStreamReader instance.
        """
        super().__init__(limit, loop)

    async def read_reply(self):
        """
        Reads a reply from the server.

        Raises SMTPServerDisconnectedError if EOF is reached.

        Returns a (code, full_message) tuple consisting of:

        * server response code (or -1 if the code can't be read from server) ;
        * server response string corresponding to response code (multiline
          responses are converted to a single, multiline string).
        """
        code = -1
        messages = []

        go_on = True

        while go_on:
            try:
                line = await self.readline()
            except ValueError as e:
                # ValueError is raised when limit is reached before we could
                # get an entire line.
                raise SMTPResponseLineTooLongError()

            # FIXME: what should we do when getting an empty line ?
            # if not line:
            #     ...

            try:
                code = int(line[:3])
            except ValueError:
                code = -1
                go_on = False
            else:
                # Check is we have a multiline response:
                go_on = (line[3:4] == b'-')

            message = line[4:].strip(b' \t\r\n').decode('ascii')
            messages.append(message)

        full_message = "\n".join(messages)

        return code, full_message


class SMTPStreamWriter(StreamWriter):
    """
    """
    def __init__(self, transport, protocol, reader, loop):
        """
        Initializes a new SMTPStreamWriter instance.
        """
        super().__init__(transport, protocol, reader, loop)

    async def send_command(self, *args):
        """
        Sends the given command (and parameters, if any) to the server.
        
        Raises ConnectionResetError when the connection is lost.
        """
        command = "{}\r\n".format(" ".join(args)).encode('ascii')

        self.write(command)

        # Don't forget to drain or the command will stay buffered:
        await self.drain()
