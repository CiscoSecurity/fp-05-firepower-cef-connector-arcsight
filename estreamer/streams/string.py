
#********************************************************************
#      File:    string.py
#      Author:  Sam Strachan
#
#      Description:
#       This gives a stream interface to a string.
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
from estreamer.streams.base import Base

class StringStream( Base ):
    """String writer shim"""
    def __init__( self ):
        self.list = []

    def write( self, value ):
        """Writes "value" to the buffer"""
        if not isinstance( value, basestring ):
            string = str( value )
        else:
            string = value
        self.list.append(string)

    def string( self ):
        """Returns the buffer as a string"""
        return "".join( self.list )
