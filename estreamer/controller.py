"""
The main controller for the system. It creates, starts and manages all the
sub processes for receiving, parsing, decorating, transforming and writing
messages
"""
#********************************************************************
#      File:    controller.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       This file contains the primary controller class for the
#       eStreamer-eNcore client
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

import json
import os
import datetime
import math
import multiprocessing
import platform
import sys

import estreamer
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
from estreamer.baseproc import ProcessProxy

import estreamer.pipeline

#pylint: disable=W0703
class Controller( object ):
    """
    The main controller for the system. It creates, starts and manages all the
    sub processes for receiving, parsing, decorating, transforming and writing
    messages
    """
    MAX_WORKERS = 12
    MIN_WORKERS = 5
    RESERVED_WORKERS = 3

    def __init__( self, settings ):
        self.state = definitions.STATE_STOPPED
        self.logger = estreamer.crossprocesslogging.getLogger(
            self.__class__.__name__ )

        self.monitor = estreamer.Monitor( self, settings )

        self.parserQueue = multiprocessing.Queue( maxsize = settings.queueSize )
        self.decoratorQueue = multiprocessing.Queue( maxsize = settings.queueSize )
        self.transformQueue = multiprocessing.Queue( maxsize = settings.queueSize )
        self.writerQueue = multiprocessing.Queue( maxsize = settings.queueSize )

        self.processes = []

        self.startTime = datetime.datetime.now()
        self.settings = settings
        self.pid = os.getpid()



    def _createProcesses1( self ):
        self.processes.append( ProcessProxy(
            name = 'worker',
            function = estreamer.pipeline.SingleWorker,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = None,
            outputQueue = None ) )



    def _createProcesses2( self ):
        self.processes.append( ProcessProxy(
            name = 'subscriberParserDecorator',
            function = estreamer.pipeline.SubscriberParserDecorator,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = None,
            outputQueue = self.transformQueue ) )

        self.processes.append( ProcessProxy(
            name = 'transformerWriter',
            function = estreamer.pipeline.TransformerWriter,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = self.transformQueue,
            outputQueue = None ) )



    def _createProcesses4( self ):
        self.processes.append( ProcessProxy(
            name = 'subscriberParser',
            function = estreamer.pipeline.SubscriberParser,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = None,
            outputQueue = self.decoratorQueue ) )

        self.processes.append( ProcessProxy(
            name = 'decorator',
            function = estreamer.pipeline.Decorator,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = self.decoratorQueue,
            outputQueue = self.transformQueue ) )

        self.processes.append( ProcessProxy(
            name = 'transformer',
            function = estreamer.pipeline.Transformer,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = self.transformQueue,
            outputQueue = self.writerQueue ) )

        self.processes.append( ProcessProxy(
            name = 'writer',
            function = estreamer.pipeline.Writer,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = self.writerQueue,
            outputQueue = None ) )



    def _createProcessesN( self, workerProcesses ):
        # We're going to have:
        #   1 Subscriber
        #   n Parsers
        #   1 Decorator
        #   n Transformers
        #   1 Writer
        #
        # Of the single instance queues, the decorator is the slowest, writer is
        # the fastest and the subscriber is limited by the network.
        #
        # The Transformer and Parser are approximately the same speed and are
        # about 4 times slower than the decorator. That said, the parser is
        # slightly slower, so prefer that. In other words, there is no
        # point in having more than about 4 Parsers / Transformers. Or 11 in total
        #
        # We'll allow 12
        if workerProcesses > Controller.MAX_WORKERS:
            self.logger.info('Limiting worker processes to {0}'.format(
                Controller.MAX_WORKERS ))

            workerProcesses = Controller.MAX_WORKERS

        elif workerProcesses < 5:
            self.logger.error('System error. Worker processes to {0}'.format(
                Controller.MAX_WORKERS ))

        availableWorkers = float( workerProcesses - Controller.RESERVED_WORKERS )
        parserCount = int( math.ceil( availableWorkers / 2 ) )
        transformerCount = int( math.floor( availableWorkers / 2 ) )

        self.processes.append( ProcessProxy(
            name = 'subscriber',
            function = estreamer.pipeline.Subscriber,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = None,
            outputQueue = self.parserQueue ) )

        for index in range( 0, parserCount ):
            self.processes.append( ProcessProxy(
                name = 'parser {0}'.format( index ),
                function = estreamer.pipeline.Parser,
                settings = self.settings,
                loggingQueue = estreamer.crossprocesslogging.queue(),
                inputQueue = self.parserQueue,
                outputQueue = self.decoratorQueue ) )

        self.processes.append( ProcessProxy(
            name = 'decorator',
            function = estreamer.pipeline.Decorator,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = self.decoratorQueue,
            outputQueue = self.transformQueue ) )

        for index in range( 0, transformerCount ):
            self.processes.append( ProcessProxy(
                name = 'transformer {0}'.format( index ),
                function = estreamer.pipeline.Transformer,
                settings = self.settings,
                loggingQueue = estreamer.crossprocesslogging.queue(),
                inputQueue = self.transformQueue,
                outputQueue = self.writerQueue ) )

        self.processes.append( ProcessProxy(
            name = 'writer',
            function = estreamer.pipeline.Writer,
            settings = self.settings,
            loggingQueue = estreamer.crossprocesslogging.queue(),
            inputQueue = self.writerQueue,
            outputQueue = None ) )



    def _createProcesses( self ):
        if self.settings.workerProcesses == 1:
            self._createProcesses1()

        elif self.settings.workerProcesses == 2:
            self._createProcesses2()

        elif self.settings.workerProcesses < 5:
            self._createProcesses4()

        else:
            self._createProcessesN( self.settings.workerProcesses )



    def start( self ):
        """Starts the service"""
        # Start the log service before anything else
        self.logger.info( 'eNcore version: {0}'.format( self.settings.version ))
        self.logger.info( 'Python version: {0}'.format( sys.version ))
        self.logger.info( 'Platform version: {0}'.format( platform.platform() ))
        self.logger.info( 'Starting client (pid={0}).'.format( self.pid ))
        self.logger.info( 'Sha256: {0}'.format( self.settings.sha256 ))
        self.logger.info( 'Processes: {0}'.format( self.settings.workerProcesses ))
        self.logger.info( 'Settings: {0}'.format( self.settings.toBase64() ))

        # It would be nice to output our local IP addresses - useful for logs. The problem
        # is that we may have a few. TODO

        self.state = definitions.STATE_STARTING

        # Do diagnostics next
        try:
            diagnostics = estreamer.Diagnostics( self.settings )
            diagnostics.execute()

        except Exception as ex:
            self.logger.exception( ex )

            self.saveState({
                'state': {
                    'id': definitions.STATE_ERROR,
                    'description': ex.message
                }
            })

            self.state = definitions.STATE_ERROR
            return

        # If we get here then things should work
        self._createProcesses()
        for process in self.processes:
            process.start()

        self.monitor.start()

        self.state = definitions.STATE_RUNNING



    def status( self ):
        """Returns an object describing the client status"""
        duration = datetime.datetime.now() - self.startTime
        status = {
            'start': self.startTime.isoformat(),
            'now': datetime.datetime.now().isoformat(),
            'duration': duration.total_seconds(),
            'bookmark': 0,
            'events': 0,
            'cumulative_rate': 0,
            'processes': [],
            'state': {
                'id': self.state,
                'description': definitions.STATE_STRING[self.state]
            }
        }

        # Sending pipes to processes which are not running or shutting down
        # will lead to errors and deadlocks. Loop through to detect errors.
        if self.state == definitions.STATE_RUNNING:
            # Loop through all processes and just check we're running properly
            for proxy in self.processes:
                if not proxy.process.is_alive():
                    self.logger.info( 'Process {0} is dead.'.format( proxy.name ))
                    self.state = definitions.STATE_ERROR
                    break

                if proxy.request( 'status' )['state'] == definitions.STATE_ERROR:
                    self.logger.info( 'Process {0} state is {1}.'.format(
                        proxy.name,
                        definitions.STATE_STRING[ definitions.STATE_ERROR ]
                    ))

                    self.state = definitions.STATE_ERROR
                    break

        # Now do the actual status checks
        if self.state == definitions.STATE_RUNNING:
            # Loop through processes in order
            for proxy in self.processes:
                response = proxy.request('status')

                proc = {
                    'name': proxy.name,
                    'pid': proxy.process.pid,
                    'count': response['count'],
                    'sleep': response['sleep']
                }

                status['events'] = proc['count']
                status['processes'].append( proc )

                if 'bookmark' in response:
                    status['bookmark'] = response['bookmark']

            status['cumulative_rate'] = round(
                status['events'] / duration.total_seconds(), 2)

        return status



    def saveState( self, state ):
        """Saves the status to disk"""
        with open( self.settings.statusFilepath(), 'w' ) as statusFile:
            json.dump( {
                'state': state
            }, statusFile )



    def __stop( self ):
        if self.state != definitions.STATE_STOPPING:
            self.state = definitions.STATE_STOPPING
            self.logger.info( 'Stopping...' )

            # Stop processes in order - as they're in the pipeline. The earlier
            # pipeline items put stuff on the queue which will stop the process
            # terminating properly if those items are not consumed. This is
            # potentially avoidable using
            # https://docs.python.org/2/library/multiprocessing.html#multiprocessing.Queue.cancel_join_thread
            # See more here:
            # https://docs.python.org/2/library/multiprocessing.html#multiprocessing-programming
            while len( self.processes ) > 0:
                proxy = self.processes[0]

                if proxy.process.is_alive():
                    # Send a stop message but don't wait for a response. It's possible
                    # it's already in an error condition / dying and can't reply. Its
                    # reply is that it finishes.
                    proxy.request( 'stop' )
                    proxy.process.join()

                self.logger.info( 'Process {0} ({1}) exit code: {2}'.format(
                    proxy.process.pid,
                    proxy.process.name,
                    proxy.process.exitcode ) )

                del self.processes[0]


            self.monitor.stop()
            self.logger.info( 'Goodbye' )
            self.state = definitions.STATE_STOPPED
            self.saveState( self.status()['state'] )



    def stop( self, parentPid ):
        """
        Sends a stop signal to subscribers and handlers to stop the
        service
        """
        if parentPid != os.getpid():
            self.logger.debug( 'Stop signal received but pids do not match' )
            return

        self.__stop()
