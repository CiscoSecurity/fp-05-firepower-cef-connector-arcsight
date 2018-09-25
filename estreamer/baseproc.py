
#********************************************************************
#      File:    baseproc.py
#      Author:  Sam Strachan
#
#      Description:
#       This file models a process. It should be inherited by
#       any class which needs to run as its own process
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

import multiprocessing
import Queue
import time
import threading

import estreamer
import estreamer.crossprocesslogging as logging
import estreamer.definitions as definitions

# We are allowed to catch Exceptions here
#pylint: disable=W0703

class BaseProcess( object ):
    """
    The BaseProcess class implements a common sub process with control commands
    """
    def __init__( self, settings, parentPipe, logQueue ):
        self.settings = settings
        self.pipe = parentPipe
        self.logQueue = logQueue
        self.checkMessagesPeriod = 1

        # Configure logging first
        logging.init( logQueue, settings.logging.levelId )

        self.logger = logging.getLogger( self.__class__.__name__ )

        self.state = definitions.STATE_STOPPED



    def stop( self ):
        """Changes the state to not-running"""
        self.state = definitions.STATE_STOPPING



    def status( self ):
        """
        Returns a dictionary containing vital statistcs. This is used by the
        status request pipe
        """
        return {
            'state': self.state
        }



    def _handleControlCommand( self, command ):
        if command == 'stop':
            self.pipe.send( 'ok' )
            self.logger.info('Stop message received')
            self.stop()

        elif command == 'status':
            self.pipe.send( self.status() )

        else:
            raise estreamer.EncoreException(
                'Unknown command: {0}'.format( command ))



    def _checkControlCommands( self ):
        if self.pipe.poll():
            command = self.pipe.recv()
            self._handleControlCommand( command )



    def _start( self, callback ):
        """
        Starts the process. It will continue until stopped. Stopping will
        typically be controlled by the parent process sending a 'stop' message
        via a pipe
        """
        try:
            self.logger.info( 'Starting process.' )
            self.logger.debug( '{0}'.format( self.__class__.__name__ ))

            self.state = definitions.STATE_RUNNING
            index = 0
            while self.state == definitions.STATE_RUNNING:
                index += 1

                # Check pipe for control messages
                if index == self.checkMessagesPeriod:
                    self._checkControlCommands()
                    index = 0

                if callable( callback ):
                    callback()

        except KeyboardInterrupt:
            self.logger.info('KeyboardInterrupt: shutdown')
            self.state = definitions.STATE_ERROR

        except Exception as ex:
            self.logger.exception(ex)
            self.state = definitions.STATE_ERROR



class QueueProcess( BaseProcess ):
    """
    Models a process which has an input and output queue. It handles sleeping
    in between upstream and downstream requests as well as responding to queries
    and shutting down
    """
    def __init__( self, settings, parentPipe, logQueue, inputQueue, outputQueue ):
        self.inputQueue = inputQueue
        self.outputQueue = outputQueue
        self.count = 0
        self.sleepInputDuration = 0
        self.sleepOutputDuration = 0
        super( QueueProcess, self ).__init__( settings, parentPipe, logQueue )
        self.start()



    def _logMessage( self, message ):
        if len( message ) < self.settings.logging.maximumLength:
            self.logger.error( 'Message data: {0}'.format( message ) )

        elif self.logger.isEnabledFor( logging.DEBUG ):
            self.logger.debug( 'Message data: {0}'.format( message ) )

        else:
            self.logger.error( 'Message data too large. Enable debug if asked to do so.' )



    def sleepInput( self, duration ):
        """
        Puts the process to sleep for duration and logs that we're waiting for
        input
        """
        self.sleepInputDuration += duration
        time.sleep( duration )



    def sleepOutput( self, duration ):
        """
        Puts the process to sleep for duration and logs that we're waiting for
        output
        """
        self.sleepOutputDuration += duration
        time.sleep( duration )



    def status( self ):
        return {
            'count': self.count,
            'state': self.state,
            'sleep': {
                'input': round( self.sleepInputDuration, 2 ),
                'output': round( self.sleepOutputDuration, 2 )
            }
        }



    def onReceive( self, item ):
        """
        Occurs when we receive a message from the queue
        """
        self.onEvent( item )
        self.count += 1



    def onEvent( self, event ):
        """
        Occurs when we receive an event. You want to override this method
        """
        pass



    def receiveInput( self ):
        """
        Attempts to read from the input queue and fires onReceive() if
        applicable
        """
        try:
            item = self.inputQueue.get( False )
            self.onReceive( item )

        except Queue.Empty:
            self.sleepInput( definitions.TIME_BLINK )

        # For now we want to continue on errors
        except estreamer.EncoreException as ex:
            encodedMessage = estreamer.adapters.base64.dumps( item )
            self.logger.error( ex )
            self._logMessage( encodedMessage )

        except Exception as ex:
            self.logger.exception(ex)
            encodedMessage = estreamer.adapters.base64.dumps( item )
            self._logMessage( encodedMessage )
            self.state = definitions.STATE_ERROR



    def sendOutput( self, event ):
        """
        Sends a message on to the output queue
        """
        if self.outputQueue:
            while self.state == definitions.STATE_RUNNING:
                try:
                    self.outputQueue.put( event, False )
                    return

                except Queue.Full:
                    self.sleepOutput( definitions.TIME_BLINK )



    def _awaitDeath( self ):
        if self.state == definitions.STATE_STOPPED:
            return

        # We have two queues. We control what gets put in the output, but not
        # the input. So, stop putting anything in the output and continue to
        # clear the input queue in order to avoid deadlocking
        self.logger.info( 'Error state. Clearing queue' )
        try:
            while self.state == definitions.STATE_ERROR:
                # Check pipe for control messages
                self._checkControlCommands()

                # Throw queue away
                try:
                    self.inputQueue.get( False )

                except Queue.Empty:
                    self.sleepInput( definitions.TIME_BLINK )

                self.receiveInput()

        except Exception as ex:
            self.logger.exception(ex)

        self.settings.close()
        self.logger.info( 'Exiting' )



    def start( self ):
        """
        Starts the main loop and calls receiveInput for each iteration.
        It will continue until stopped. Stopping will typically be controlled
        by the parent process sending a 'stop' message via a pipe
        """
        # Starts the main loop
        self._start( self.receiveInput )

        # If we get here then something has gone wrong or we've been stopped
        self._awaitDeath()



class BatchQueueProcess( QueueProcess ):
    """
    Inherits a QueueProcess but implements message batching for additional
    performance
    """
    def __init__( self, settings, parentPipe, logQueue, inputQueue, outputQueue ):
        self.batch = []
        super( BatchQueueProcess, self ).__init__(
            settings,
            parentPipe,
            logQueue,
            inputQueue,
            outputQueue )



    def sendOutput( self, event ):
        self.batch.append( event )

        if len( self.batch ) % self.settings.batchSize == 0:
            super( BatchQueueProcess, self ).sendOutput( self.batch )
            self.batch = []



    def onReceive( self, items ):
        for item in items:
            self.onEvent( item )
            self.count += 1



class ProcessProxy( object ):
    """
    Wraps one of the baseproc Process classes and maintains a link for comms
    """
    def __init__(
            self,
            name,
            function,
            settings,
            loggingQueue,
            inputQueue,
            outputQueue ):

        self.logger = logging.getLogger( __name__ )
        self.name = name
        self.function = function
        self.settings = settings
        self.loggingQueue = loggingQueue
        self.inputQueue = inputQueue
        self.outputQueue = outputQueue
        self.pipe = None
        self.process = None



    def start( self ):
        """
        Starts the remoate process
        """
        ( one, two ) = multiprocessing.Pipe()
        self.pipe = one

        self.process = multiprocessing.Process(
            target = self.function,
            args = (
                self.settings,
                two,
                self.loggingQueue,
                self.inputQueue,
                self.outputQueue ) )

        # Make this a daemon process so that if anything catastrophic happens to this
        # parent then the child will stop too.
        self.process.daemon = True
        self.process.start()



    def request( self, req ):
        """
        Sends a pipe request to the remote process
        """
        # Ignoring a receive can lead to messages getting out of sync
        # we'll try and avoiding timeouts by waiting a bit longer
        # than the response timeout
        lock = threading.Lock()
        lock.acquire()

        try:
            self.pipe.send( req )
            available = self.pipe.poll( self.settings.responseTimeout + 5 )
            if available:
                return self.pipe.recv()

            raise estreamer.TimeoutException(
                'ProxyProcess[name={0}].request({1}) timeout'.format(
                    self.name,
                    req ))

        finally:
            lock.release()
