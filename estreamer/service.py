#!/usr/bin/env python
#********************************************************************
#      File:    service.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       The main entry point of the software
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

from __future__ import print_function
import argparse
import os
import signal
import sys
import time

# Use this to avoid pyc bytecode everywhere
sys.dont_write_bytecode = True

# Path hack.
WORKING_DIRECTORY = os.path.abspath( os.path.dirname( __file__ ) + '/..')
sys.path.append( WORKING_DIRECTORY )

# Allow late imports,Exception
#pylint: disable=C0413,W0703,E1101,W0613
import estreamer.condition
import estreamer.controller
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
import estreamer


class Service ( object ):
    """
    The Service class is the main entry point of the software. It manages the creation and
    management of resources, loggers, processes and settings.
    """
    def __init__( self ):
        self.logServer = None
        self.logger = None
        self.client = None
        self.settingsFilepath = None
        self.pid = os.getpid()
        self.conditions = []



    def _loop( self ):
        self.client.start()
        while self.client.state != definitions.STATE_STOPPED:
            if self.client.state == definitions.STATE_ERROR:
                self.client.stop( self.pid )

                if self.client.settings.alwaysAttemptToContinue:
                    time.sleep( definitions.TIME_PAUSE )
                    self.client.start()

            for condition in self.conditions:
                if not condition.isTrue():
                    self.logger.info( condition.message() )
                    self.logger.info('Stopping')
                    time.sleep( definitions.TIME_PAUSE )
                    self.client.stop( self.pid )

            time.sleep( definitions.TIME_PAUSE )



    def _posix( self ):
        def _dump( signum, stack ):
            if self.client:
                print ( str( self.client.status() ))

        def _stop( signum, stack ):
            if self.client:
                self.client.stop( self.pid )

        signal.signal( signal.SIGUSR1, _dump )
        signal.signal( signal.SIGINT, _stop )
        signal.signal( signal.SIGTERM, _stop )

        self._loop()



    def _windows( self ):
        self.conditions.append( estreamer.condition.WindowsCondition() )

        try:
            self._loop()

        except KeyboardInterrupt:
            self.client.stop( self.pid )



    def start( self, reprocessPkcs12 = False ):
        """
        Creates settings, configures logging, creates the main client and then runs platform
        specific code to handle system interupts
        """
        # Start off with a simple StdOut logger incase things really go wrong
        self.logger = estreamer.crossprocesslogging.StdOutClient(
            self.__class__.__name__,
            estreamer.crossprocesslogging.DEBUG)

        # Create settings
        settings = estreamer.Settings.create( self.settingsFilepath )

        # Configure and initialise logging ASAP
        self.logServer = estreamer.crossprocesslogging.Server(
            emitSourceTime = settings.logging.emitSourceTime,
            queueSize = settings.queueSize)

        self.logServer.start()
        estreamer.crossprocesslogging.configure( settings )
        estreamer.crossprocesslogging.init( self.logServer.queue, settings.logging.levelId )
        self.logger = estreamer.crossprocesslogging.getLogger( self.__class__.__name__ )

        # Always add enabled condition
        self.conditions.append( estreamer.condition.EnabledCondition( self.settingsFilepath ) )

        for condition in settings.conditions:
            self.conditions.append( estreamer.condition.create( condition ))

        # Create pid reference
        pidFile = estreamer.PidFile( settings.pidFilepath() )

        # Now do some more checks
        if settings.enabled:
            pidFile.create()

            if reprocessPkcs12:
                settings.reprocessPkcs12 = True

            # Create the client
            self.client = estreamer.Controller( settings )

            if os.name == 'posix':
                self._posix()

            elif os.name == 'nt':
                self._windows()

            pidFile.destroy()

        else:
            self.logger.info('settings.enabled == False. Stopping')



    def main( self ):
        """
        Command line entry point which manages arguments and then calls Service.start()
        """
        try:
            parser = argparse.ArgumentParser(description='Runs eStreamer eNcore')
            parser.add_argument(
                'configFilepath',
                help = 'The filepath of the config file')

            parser.add_argument(
                '--pkcs12',
                action = "count",
                help = 'Reprocess pkcs12 file')

            args = parser.parse_args()

            self.settingsFilepath = args.configFilepath

            self.start( reprocessPkcs12 = args.pkcs12 )


        except estreamer.EncoreException as ex:
            self.logger.error(ex)

        except KeyboardInterrupt:
            self.logger.info('KeyboardInterrupt: shutdown')

        except Exception as ex:
            self.logger.exception(ex)

        if self.logServer:
            self.logServer.stop()



if __name__ == '__main__':
    Service().main()
