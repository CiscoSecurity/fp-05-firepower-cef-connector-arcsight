
#********************************************************************
#      File:    scp.py
#      Author:  Sam Strachan
#
#      Description:
#       Encapsulates a file output stream and then scps once finished
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

from __future__ import absolute_import

import os
import subprocess
import estreamer
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
import estreamer.common.convert as convert
from estreamer.streams.file import FileStream

class ScpStream( FileStream ):
    """Class for writing output to a rotated log file"""

    ALWAYS_USE_LIBRARY = True

    STRING_USING_CLI = "No scp library found. Using command line. Consider `pip install scp`"
    STRING_INSTALL_SCP = "No scp library found. Install scp e.g. `pip install scp`"
    STRING_NON_POSIX_SCP = """No scp library or command line. You must `pip install scp`'"""

    def __init__( self, directory, threshold, rotate, filename,
                  uri, scpKeyFilepath, encoding = 'utf-8',
                  deleteOnTransfer = True ):

        super( ScpStream, self ).__init__(
            directory,
            threshold,
            rotate,
            filename,
            encoding )

        self.logger = estreamer.crossprocesslogging.getLogger( __name__ )

        self.uri = uri
        self.scpKeyFilepath = scpKeyFilepath
        self.port = 22
        self.deleteOnTransfer = deleteOnTransfer
        self.transfer = None
        self._setHandler()

        if self.uri.port:
            if convert.isUint16( self.uri.port ):
                self.port = self.uri.port

            else:
                raise estreamer.EncoreException(
                    definitions.STRING_INVALID_PORT.format( self.uri.port ) )



    def _setHandler( self ):
        if self.transfer is None:
            try:
                import scp
                self.transfer = self._scpLibrary

            except ImportError:
                # EncoreExceptions are caught and re-attempted. We want a force stop.
                # So use plain Exception instead

                if ScpStream.ALWAYS_USE_LIBRARY:
                    raise Exception( ScpStream.STRING_INSTALL_SCP )

                elif os.name != 'posix':
                    raise Exception( ScpStream.STRING_NON_POSIX_SCP )

                else:
                    self.logger.warning( ScpStream.STRING_USING_CLI )

                self.transfer = self._scpCommandLine



    def _scpCommandLine( self ):
        scpConnectionString = '{0}@{1}:{2}/'.format(
            self.uri.userinfo,
            self.uri.host,
            self.uri.path )

        filepath = os.path.realpath( self.file.name )
        cmds = [
            'scp',
            '-P {0}'.format( self.port ),
            filepath,
            scpConnectionString
        ]

        # Run the output - and collect stderr too - into this string
        # This is a temporary approach just to get it working
        subprocess.check_output(
            cmds,
            stderr = subprocess.STDOUT )

        self.logger.info( ' '.join( cmds ) )



    def _scpLibrary( self ):
        from paramiko import SSHClient
        from paramiko import AutoAddPolicy
        from scp import SCPClient

        ssh = SSHClient()
        ssh.set_missing_host_key_policy( AutoAddPolicy )
        ssh.connect(
            hostname = self.uri.host,
            port = self.port,
            username = self.uri.userinfo,
            key_filename = self.scpKeyFilepath )

        filepath = os.path.realpath( self.file.name )

        with SCPClient( ssh.get_transport() ) as scpClient:
            scpClient.put( filepath, self.uri.path )

        self.logger.info( 'scplib: {0} complete'.format( filepath ) )



    def onFileClose( self ):
        self.transfer()

        # Now delete file
        if self.deleteOnTransfer:
            os.remove( self.file.name )
