"""
The streams module contains classes which actually take care of
writing to a resource. It could be a file, stdout or maybe a
database. Each class MUST have a write( record ) method
"""
#********************************************************************
#      File:    __init__.py
#      Author:  Sam Strachan
#
#      Description:
#       streams package
#
#      Copyright (c) 2017 by Cisco Systems, Inc.
#
#       ALL RIGHTS RESERVED. THESE SOURCE FILES ARE THE SOLE PROPERTY
#       OF CISCO SYSTEMS, Inc. AND CONTAIN CONFIDENTIAL  AND PROPRIETARY
#       INFORMATION.  REPRODUCTION OR DUPLICATION BY ANY MEANS OF ANY
#       PORTION OF THIS SOFTWARE WITHOUT PRIOR WRITTEN CONSENT OF
#       CISCO SYSTEMS, Inc. IS STRICTLY PROHIBITED.
#
#*********************************************************************/
import sys

from estreamer.streams.file import FileStream
from estreamer.streams.string import StringStream
from estreamer.streams.logger import LoggerStream
from estreamer.streams.udp import UdpStream
from estreamer.streams.tcp import TcpStream
from estreamer.streams.scp import ScpStream
from estreamer.common.uri import Uri
from estreamer import EncoreException

def create( settingsStream ):
    """Factory method to create a stream"""
    uri = Uri( settingsStream.uri )

    if uri.scheme == 'file' or uri.scheme == 'relfile':
        maxLogs = 10000
        rotate = True

        if 'rotate' in settingsStream.options:
            rotate = settingsStream.options['rotate']

        if 'maxLogs' in settingsStream.options:
            maxLogs = settingsStream.options['maxLogs']

        stream = FileStream( uri.path, maxLogs, rotate, uri.file )
        return stream

    elif uri.scheme == 'udp':
        stream = UdpStream( uri.host, uri.port )
        return stream

    elif uri.scheme == 'tcp':
        stream = TcpStream( uri.host, uri.port )
        return stream

    elif uri.scheme == 'string':
        return StringStream()

    elif uri.scheme == 'scp':
        rotate = True
        maxLogs = 500
        if 'maxLogs' in settingsStream.options:
            maxLogs = settingsStream.options['maxLogs']

        tempDir = './'

        scpKeyFilepath = None
        if 'scpKeyFilepath' in settingsStream.options:
            scpKeyFilepath = settingsStream.options['scpKeyFilepath']

        stream = ScpStream(
            directory = tempDir,
            threshold = maxLogs,
            rotate = rotate,
            filename = uri.file,
            uri = uri,
            scpKeyFilepath = scpKeyFilepath )

        return stream

    else:
        return sys.stdout
