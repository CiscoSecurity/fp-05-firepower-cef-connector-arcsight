
#********************************************************************
#      File:    monitor.py
#      Author:  Sam Strachan
#
#      Description:
#       The monitor runs a spearate thread to keep an eye on the client
#       and return current status information
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

import threading
import time
import estreamer.definitions as definitions
import estreamer.crossprocesslogging as logging
import estreamer

#pylint: disable=W0703

class Monitor( object ):
    """Helper class which monitors the state of the client and takes any
    necessary action on failures or timed events"""
    def __init__( self, client, settings ):
        self.client = client
        self.settings = settings
        self.logger = logging.getLogger( self.__class__.__name__ )
        self.state = definitions.STATE_STOPPED
        self.thread = None

        self.lastCount = 0
        self.lastBookmark = 0
        self.lastTick = 0



    def __stats( self, bookmark, count ):
        now = time.time()

        # Number of seconds through time since last go
        dBookmark = bookmark - self.lastBookmark

        # Actual time since last go
        dTime = now - self.lastTick

        # Count diff
        dCount = count - self.lastCount

        # Distance travelled (with direction)
        distance = dBookmark - dTime

        # Velocity
        velocity = distance / dTime
        rate = dCount / dTime

        self.lastBookmark = bookmark
        self.lastTick = now
        self.lastCount = count

        return velocity, rate



    def __tick( self ):
        try:
            status = self.client.status()

            self.client.saveState( status['state'] )

            if self.settings.monitor.details:
                self.logger.info( str(status) )

            if self.logger.isEnabledFor( logging.INFO ):
                message = '{0}.'.format( status['state']['description'] )

                if self.settings.monitor.handled:
                    message += ' {0} handled;'.format( status['events'] )

                if self.client.status:
                    message += ' average rate {0} ev/sec; '.format(status['cumulative_rate'])

                if self.settings.monitor.bookmark:
                    message += ' bookmark {0};'.format(
                        estreamer.common.convert.toIso8601( status['bookmark'] ))

                self.logger.info( message )

        except estreamer.UnsupportedTimestampException:
            # This is a workaround for the time being. Occasionally, on stopping
            # the controlling process pipe communications collides with the monitor
            # and messages are garbled. Investigate
            self.logger.info('Running (no process data available)')

        except estreamer.EncoreException as ex:
            self.logger.error(ex)

        except Exception as ex:
            self.logger.exception(ex)



    def __start( self ):
        nextTick = time.time()

        try:
            while self.state == definitions.STATE_RUNNING:
                nextTick += self.settings.monitor.period
                self.__tick()

                # If we get here and we are ALREADY beyond the next tick then
                # either the monitorPeriod is too short or pipe comms are too
                # slow. Either way, kick the can down the road
                while nextTick < time.time():
                    nextTick += self.settings.monitor.period

                # Check every quarter second to see if we're running
                while time.time() < nextTick and self.state == definitions.STATE_RUNNING:
                    time.sleep( 0.25 )

        except Exception as ex:
            self.logger.error('Monitor __start: {0}'.format( ex ))
            self.state = definitions.STATE_ERROR



    def start( self ):
        """Starts a background thread to monitor the client"""
        self.logger.info('Starting Monitor.')
        self.state = definitions.STATE_RUNNING
        self.thread = threading.Thread( target = self.__start )
        self.thread.daemon = True
        self.thread.start()



    def stop( self ):
        """Stops the background monitoring thread"""
        if self.logger is not None:
            self.logger.info('Stopping Monitor.')

        self.state = definitions.STATE_STOPPING

        if self.thread is not None:
            self.thread.join()

        self.state = definitions.STATE_STOPPED
