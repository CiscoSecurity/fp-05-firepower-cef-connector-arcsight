
#********************************************************************
#      File:    base.py
#      Author:  Sam Strachan
#
#      Description:
#       Base stream interface. It is essentially an abstract class
#       in that it has no implementation
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

class Base( object ):
    """Base implementation of stream which ensures write( data ) and close()"""
    def close( self ):
        """Closes the stream and any related resources"""
        pass

    def write( self, data ):
        """Writes data to the stream"""
        pass
