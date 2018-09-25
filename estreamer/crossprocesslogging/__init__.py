"""
Logging is not multiprocess compatible, so settings are not shared. This
module gets around that limitation and more-or-less reproduces the logger
interface.

The way it works is for each child process to call:

    estreamer.crossprocesslogging.init( serverQueue, level )

at the start of its invocation. the serverQueue is sent from the parent
process. This sets a singleton / global queue for *the process*

    estreamer.crossprocesslogging.getLogger( name )

then uses that singleton and returns an instance of the ...

    estreamer.crossprocesslogging.client

class (in this module) which mimics the standard interface. [If you find it's
missing anything, feel free to add.] Underneath its implementation it
serialises the message, level and loggerName and puts it into the serverQueue.

The server queue runs in the parent process and kicks off its own thread to
process the items in the queue.
"""
#********************************************************************
#      File:    __init__.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       crossprocesslogging package
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

#pylint: disable=W0401,W0603,C0103,C0413
from __future__ import absolute_import
from __future__ import print_function
import logging as __logging
import sys
import estreamer


# Enabled is true by default. If you are running in a single-process
# environment then this must be overridden to False
IsMultiProcess = True
Print = False

#pylint: disable=C0103

# Trace stands a chance of impacting performance so much that this is
# completely unusable. It is prone to output tens or hundreds of lines
# per record. Use with caution
TRACE = 1

# Verbose is for where debug isn't enough. It should output no more than
# a few lines per record.
VERBOSE = 5

DEBUG = __logging.DEBUG
INFO = __logging.INFO
WARNING = __logging.WARNING
ERROR = __logging.ERROR
FATAL = __logging.FATAL

LevelStrings = {
    TRACE: 'TRACE',
    VERBOSE: 'VERBOSE',
    DEBUG: 'DEBUG',
    INFO: 'INFO',
    WARNING: 'WARNING',
    ERROR: 'ERROR',
    FATAL: 'FATAL'
}

# Imports placed lower in order to use items above
from estreamer.crossprocesslogging.client import Client
from estreamer.crossprocesslogging.stdOutClient import StdOutClient
from estreamer.crossprocesslogging.server import Server

# This is the serverQueue per *process*
__serverQueueInstance = None
__logLevelId = 0

def init( serverQueue, logLevelId ):
    """Call init() once at the start of each process"""
    global __serverQueueInstance
    global __logLevelId
    if IsMultiProcess:
        if __serverQueueInstance is None:
            if Print:
                print( 'Creating server queue' )
            __serverQueueInstance = serverQueue
            __logLevelId = logLevelId



def getLogger(name = None):
    """Gets the multi-process aware logger for this process"""
    if IsMultiProcess:
        if __serverQueueInstance is None:
            msg = 'Process logging not initialised. Call ' + \
                'estreamer.crossprocesslogging.init( queue, level )'
            if Print:
                print( msg )

            raise estreamer.EncoreException( msg )

        else:
            return Client(
                __serverQueueInstance,
                name,
                __logLevelId )

    else:
        return __logging.getLogger(name)



def _configure( logFilepath, logLevelId, formatString, doStdOut, doStdErr ):
    rootLogger = __logging.getLogger()
    rootLogger.setLevel( logLevelId )
    rootLogger.handlers = []

    if logFilepath:
        rootLogger.addHandler( __logging.FileHandler( logFilepath ) )

    if doStdOut:
        rootLogger.addHandler( __logging.StreamHandler( sys.stdout ) )

    if doStdErr:
        rootLogger.addHandler( __logging.StreamHandler( sys.stderr ) )

    formatter = __logging.Formatter( formatString )

    for handler in rootLogger.handlers:
        handler.setFormatter( formatter )



def configure( settings ):
    """
    Sets root logging level and applies format string to all handlers. This only
    needs doing once on the server process
    """
    _configure(
        settings.logging.filepath,
        settings.logging.levelId,
        settings.logging.format,
        settings.logging.stdOut,
        settings.logging.stdErr )



def queue():
    """
    Returns the logging queue
    """
    return __serverQueueInstance
