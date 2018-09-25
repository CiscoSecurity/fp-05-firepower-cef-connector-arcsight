
#********************************************************************
#      File:    pid.py
#      Author:  Sam Strachan
#
#      Description:
#       Manages pid file
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

import os
import estreamer

class PidFile( object ):
    """The bookmark class abstracts reading, writing and managing bookmarks"""
    def __init__( self, filepath ):
        self.filepath = filepath



    def exists( self ):
        """Does the pid file already exist?"""
        return os.path.exists( self.filepath )



    def create( self ):
        """Creates the pid file - raises an exception if it already exists"""
        if self.exists():
            raise estreamer.EncoreException('PID file already exists')

        with open( self.filepath, 'w' ) as pidFile:
            pidFile.write( str( os.getpid() ) )



    def destroy( self ):
        """Removes the pid file (silent if it does not exist)"""
        try:
            os.remove( self.filepath )

        except Exception:
            pass



    def read( self ):
        """Reads the contents of the pid file returning -1 if it does not exist"""
        if not os.path.exists( self.filepath ):
            return '-1'

        with open( self.filepath, 'r' ) as reader:
            return reader.read()
