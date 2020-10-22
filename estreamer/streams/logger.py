
#********************************************************************
#      File:    logger.py
#      Author:  Sam Strachan
#
#      Description:
#       This file wraps a logger with a stream interface
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

class LoggerStream( Base ):
    """Writes to a logger at the configured level"""
    def __init__( self, logger, level ):
        self.logger = logger
        self.level = level



    def write( self, data ):
        """Writes to the underlying logger"""
        if isinstance( data, basestring ):
            data = data.strip()

        self.logger.log( self.level, data )
