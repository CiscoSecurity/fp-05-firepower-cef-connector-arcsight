
#********************************************************************
#      File:    logging.py
#      Author:  Sam Strachan
#
#      Description:
#       Logging settings
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
import logging
import estreamer.crossprocesslogging

class LoggingSettings( object ):
    """Class to define logging settings"""
    def __init__( self, loggingSettings ):
        # set defaults here
        self.filepath = None
        self.stdOut = True
        self.stdErr = False
        self.levelName = 'INFO'
        self.format = "%(asctime)s %(name)-12s %(levelname)-8s %(message)s"
        self.emitSourceTime = False
        self.maximumLength = 4096

        if loggingSettings is not None:
            if 'filepath' in loggingSettings:
                self.filepath = loggingSettings['filepath']
                if len( self.filepath.rstrip() ) == 0:
                    self.filepath = None

            if 'stdOut' in loggingSettings:
                self.stdOut = loggingSettings['stdOut']

            if 'stdErr' in loggingSettings:
                self.stdErr = loggingSettings['stdErr']

            if 'level' in loggingSettings:
                self.levelName = loggingSettings['level']

            if 'format' in loggingSettings:
                self.format = loggingSettings['format']

        self.levelId = self.__logLevelId()



    def __logLevelId( self ):
        try:
            return getattr( estreamer.crossprocesslogging, self.levelName )
        except AttributeError:
            return logging.INFO
