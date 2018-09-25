
#********************************************************************
#      File:    baseClient.py
#      Author:  Sam Strachan
#
#      Description:
#       Base client logging interface which can emit to either the
#       cross process server or the native logging
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

import logging
import time
import traceback

class BaseClient( object ):
    """Base logging client"""

    def __init__( self, name = None, level = 0 ):
        self.name = name
        self.level = level



    def __serialise( self, data, isException = False ):
        if isinstance( data, Exception ):
            message = data.__class__.__name__ + ': ' + data.message

            if isException:
                message += '\n'
                message += traceback.format_exc(data)

            return message

        else:
            return data



    def isEnabledFor( self, level ):
        """Is this logger enabled for level 'level'?"""
        return level >= self.level



    def emit( self, message ):
        """Base 'abstract' method for emitting data somewhere. message should
        look like {
            'time': time.time(),
            'name': self.name,
            'level': level,
            'data': data
        }"""
        pass



    def log( self, level, data ):
        """Logs for a specific level if applicable"""
        if self.isEnabledFor( level ):
            data = self.__serialise( data )

            self.emit({
                'time': time.time(),
                'name': self.name,
                'level': level,
                'data': data
            })



    def debug( self, data ):
        """Writes debug message to log"""
        self.log(logging.DEBUG, data)



    def info( self, data ):
        """Writes info message to log"""
        self.log(logging.INFO, data)



    def warning( self, data ):
        """Writes warning message to log"""
        self.log(logging.WARNING, data)



    def error( self, data ):
        """Writes error message to log"""
        self.log(logging.ERROR, data)



    def exception( self, data ):
        """Writes error message to log"""
        data = self.__serialise( data, True )
        self.log(logging.ERROR, data)



    def fatal( self, data ):
        """Writes exception message to log"""
        self.log(logging.FATAL, data)
