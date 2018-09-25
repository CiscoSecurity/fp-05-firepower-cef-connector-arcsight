
#********************************************************************
#      File:    server.py
#      Author:  Sam Strachan
#
#      Description:
#       Cross process logging server
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
import Queue
import time
import threading
import multiprocessing
from estreamer.common import convert
import estreamer.definitions as defininitions

class Server( object ):
    """Multi process logging server"""
    def __init__( self, emitSourceTime = False, showAlive = False, queueSize = 0 ):
        self.queue = multiprocessing.Queue( maxsize = queueSize )
        self.isRunning = False
        self.thread = None
        self.emitSourceTime = emitSourceTime
        self.showAlive = showAlive



    def __emit( self, message ):
        logger = logging.getLogger(message['name'])

        data = ''
        if self.emitSourceTime:
            data += 'srcTime={0}\t'.format(
                convert.toIso8601(message['time']))

        data += str( message['data'] )

        # We want multi-line strings to appear on one line for easier grepping
        if data.find('\n') != -1:
            data = data.replace('\n', '\\n')

        logger.log( message['level'], data )



    def __read( self ):
        """Reads an item from the logging queue and sends it to the logger"""
        try:
            message = self.queue.get( False )
            self.__emit( message )

        except Queue.Empty:
            time.sleep( defininitions.TIME_BLINK )



    def __start( self ):
        last = time.time()
        while self.isRunning:
            self.__read()
            now = time.time()

            if self.showAlive and now - last > 1:
                last = now
                self.__emit({
                    'time': now,
                    'name': __name__,
                    'level': logging.INFO,
                    'data': 'Log server alive'
                })

        while not self.queue.empty():
            self.__read()



    def start( self ):
        """Starts a background thread to process the logging queue"""
        self.isRunning = True
        self.thread = threading.Thread( target = self.__start )
        self.thread.daemon = True
        self.thread.start()



    def stop( self ):
        """Stops the background thread which picks items of the logging
        queue. Only call this once you are sure you're not sending any
        more messages into the queue. You will likely get very strange
        errors if you do"""
        self.isRunning = False
        self.thread.join()
