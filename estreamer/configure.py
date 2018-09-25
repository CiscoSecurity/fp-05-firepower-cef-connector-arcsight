
#********************************************************************
#      File:    configure.py
#      Author:  Sam Strachan
#
#      Description:
#       Configure provides an interface into writing common settings,
#       bookmarks and maintenance tasks
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
import json
import os
import sys

# Use this to avoid pyc bytecode everywhere
sys.dont_write_bytecode = True

# Path hack.
WORKING_DIRECTORY = os.path.abspath( os.path.dirname( __file__ ) + '/..')
sys.path.append( WORKING_DIRECTORY )

# Allow late imports,Exception
#pylint: disable=C0413,W0703,E1101,W0613,W0212,W0702,C0103
import argparse
import datetime
import estreamer.common.convert as convert
import estreamer.common.jsonpath as jsonpath
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
import estreamer


class Configure( object ):
    """
    Helper class which provides access to common configuration tasks
    """

    JSON_PATH_ENABLED = '$.enabled'
    JSON_PATH_CONDITIONS = '$.conditions'
    JSON_PATH_HOST = '$.subscription.servers[0].host'
    JSON_PATH_PORT = '$.subscription.servers[0].port'
    JSON_PATH_PKCS12 = '$.subscription.servers[0].pkcs12Filepath'
    JSON_PATH_STREAM0 = '$.handler.outputters[0].stream.uri'
    JSON_PATH_OUTPUT = '$.handler.outputters'
    JSON_PATH_LOGSTDOUT = '$.logging.stdOut'
    JSON_PATH_LOGSTDERR = '$.logging.stdErr'
    JSON_PATH_CONNECTIONS = '$.handler.records.connections'
    JSON_PATH_PACKETS = '$.handler.records.packets'
    JSON_PATH_METADATA = '$.handler.records.metadata'

    def __init__( self ):
        self.logger = estreamer.crossprocesslogging.getLogger( self.__class__.__name__ )
        self.filepath = None



    @staticmethod
    def _isTruish( val ):
        if val:
            if isinstance( val, basestring ):
                if val.lower() == 'true':
                    return True

                if val == '1':
                    return True

            elif val == 1:
                return True

        return False



    def _processarguments( self ):
        parser = argparse.ArgumentParser(description='Runs eStreamer eNcore Configuration')
        parser.add_argument(
            'filepath',
            help = 'The filepath of the config file')

        # Settings
        parser.set_defaults( enabled = None)

        parser.add_argument(
            '--enabled',
            help = 'Boolean - is eNcore enabled?')

        parser.add_argument(
            '--conditions',
            help = 'Conditions to evaluate in the control loop')

        parser.add_argument(
            '--logstdout',
            help = 'Should logging go to stdout?')

        parser.add_argument(
            '--logstderr',
            help = 'Should logging go to stderr?')

        parser.add_argument(
            '--host',
            help = 'FQDN or IP address of the remote FMC host')

        parser.add_argument(
            '--port',
            help = 'Port of the remote FMC host')

        parser.add_argument(
            '--stream0',
            help = 'The output URI for the main outputter')

        parser.add_argument(
            '--connections',
            help = 'Boolean - include connection statistics')

        parser.add_argument(
            '--packets',
            help = 'Boolean - include packets')

        parser.add_argument(
            '--metadata',
            help = 'Boolean - include metadata')

        parser.add_argument(
            '--output',
            help = 'splunk | cef | json')

        parser.add_argument(
            '--bookmark',
            help = 'now')

        parser.add_argument(
            '--debug',
            dest = 'debug',
            action = 'store_true')

        parser.add_argument(
            '--print',
            help = 'Prints a value to stdout')

        return parser.parse_args()



    def _bookmark( self, value ):
        if value == 'now':
            settings = estreamer.Settings.create( self.filepath )
            filepath = settings.bookmarkFilepath()

            now = datetime.datetime.utcnow()
            epoch = datetime.datetime(1970, 1, 1)
            timestamp = (now - epoch).total_seconds()
            bmark = estreamer.Bookmark( filepath )
            bmark.write( timestamp )
            bmark.save()



    def _set( self, jsonPath, value ):
        self.logger.debug('Setting {0}={1}'.format( jsonPath, value ))
        jsonpath.val( self.filepath, jsonPath, value )



    def _settings(
            self,
            enabled,
            conditions,
            output,
            host,
            port,
            stream0,
            logstdout,
            logstderr,
            connections,
            packets,
            metadata ):

        if enabled is not None:
            self._set( Configure.JSON_PATH_ENABLED, Configure._isTruish( enabled ) )

        if conditions:
            self._set( Configure.JSON_PATH_CONDITIONS, [ conditions ])

        if output == 'splunk':
            self._set( Configure.JSON_PATH_OUTPUT, [
                {
                    "adapter": "splunk",
                    "enabled": True,
                    "stream": {
                        "options": {
                            "maxLogs": 10000,
                            "rotate": True
                        },
                        "uri": "relfile:///data/splunk/encore.{0}.log"
                    }
                }
            ])

        if output == 'json':
            self._set( Configure.JSON_PATH_OUTPUT, [
                {
                    "adapter": "json",
                    "enabled": True,
                    "stream": {
                        "options": {
                            "maxLogs": 10000,
                            "rotate": True
                        },
                        "uri": "relfile:///data/json/encore.{0}.json"
                    }
                }
            ])

        if output == 'cef':
            self._set( Configure.JSON_PATH_OUTPUT, [
                {
                    "adapter": "cef",
                    "enabled": True,
                    "stream": {
                        "uri": "udp://{host}:{port}"
                    }
                }
            ])


        if host:
            self._set( Configure.JSON_PATH_HOST, host )

        if port:
            self._set( Configure.JSON_PATH_PORT, convert.infer( port ) )

        if stream0:
            self._set( Configure.JSON_PATH_STREAM0, stream0 )

        if logstdout:
            self._set( Configure.JSON_PATH_LOGSTDOUT, Configure._isTruish( logstdout ) )

        if logstderr:
            self._set( Configure.JSON_PATH_LOGSTDERR, Configure._isTruish( logstderr ) )

        if connections:
            self._set( Configure.JSON_PATH_CONNECTIONS , Configure._isTruish( connections ) )

        if packets:
            self._set( Configure.JSON_PATH_PACKETS , Configure._isTruish( packets ) )

        if metadata:
            self._set( Configure.JSON_PATH_METADATA , Configure._isTruish( metadata ) )



    def _print( self, print_ = None ):
        def _printVar( jsonPath ):
            print( jsonpath.val( self.filepath, jsonPath ) )

        if print_ == 'host':
            _printVar( Configure.JSON_PATH_HOST )

        elif print_ == 'port':
            _printVar( Configure.JSON_PATH_PORT )

        elif print_ == 'stream0':
            _printVar( Configure.JSON_PATH_STREAM0 )

        elif print_ == 'enabled':
            _printVar( Configure.JSON_PATH_ENABLED )

        elif print_ == 'pkcs12':
            _printVar( Configure.JSON_PATH_PKCS12 )

        elif print_ == 'privateKey':
            print( estreamer.Settings.create( self.filepath ).privateKeyFilepath() )

        elif print_ == 'publicKey':
            print( estreamer.Settings.create( self.filepath ).publicKeyFilepath() )

        elif print_ == 'statusFile':
            print( estreamer.Settings.create( self.filepath ).statusFilepath() )

        elif print_ == 'pidFile':
            print( estreamer.Settings.create( self.filepath ).pidFilepath() )

        elif print_ == 'stem':
            print( estreamer.Settings.create( self.filepath ).instanceFilename('') )

        elif print_ == 'pid':
            settings = estreamer.Settings.create( self.filepath )
            pidFile = estreamer.PidFile( settings.pidFilepath() )
            print( pidFile.read() )

        elif print_ == 'splunkstatus':
            settings = estreamer.Settings.create( self.filepath )
            statusFilepath = settings.statusFilepath()

            stateId = definitions.STATE_STOPPED
            stateDescription = definitions.STATE_STRING[ definitions.STATE_STOPPED ]

            try:
                with open( statusFilepath, 'r' ) as statusFile:
                    status = json.load( statusFile )
                    stateId = status['state']['id']
                    stateDescription = status['state']['description']

            except:
                pass

            splunkStatus = 'status_id={0} status=\"{1}\"'.format(
                stateId,
                stateDescription )

            print( splunkStatus )

        elif print_ == 'metadata':
            settings = estreamer.Settings.create( self.filepath )
            cache = estreamer.metadata.Cache( settings.cacheFilepath() )
            cache.load()
            output = json.dumps( cache.data )
            print ( output )



    def run(
            self,
            filepath,
            enabled = None,
            conditions = None,
            output = None,
            host = None,
            port = None,
            stream0 = None,
            logstdout = None,
            logstderr = None,
            connections = None,
            packets = None,
            metadata = None,
            bookmark = None,
            debug = None,
            print_ = None ):

        """Main entry point to configure eNcore"""
        self.filepath = filepath

        if debug:
            self.logger.setLevel( estreamer.crossprocesslogging.DEBUG )

        try:
            self._settings(
                enabled,
                conditions,
                output,
                host,
                port,
                stream0,
                logstdout,
                logstderr,
                connections,
                packets,
                metadata )

            self._bookmark( bookmark )
            self._print( print_ )

        except estreamer.EncoreException as ex:
            self.logger.error( ex )
            raise

        except Exception as ex:
            self.logger.exception( ex )
            raise



    def cli( self ):
        """
        Command line entry point which manages arguments and then calls helpers
        """
        args = self._processarguments()

        self.run(
            args.filepath,
            enabled = args.enabled,
            conditions = args.conditions,
            output = args.output,
            host = args.host,
            port = args.port,
            stream0 = args.stream0,
            logstdout = args.logstdout,
            logstderr = args.logstderr,
            connections = args.connections,
            packets = args.packets,
            metadata = args.metadata,
            bookmark = args.bookmark,
            debug = args.debug,
            print_ = args.print)



if __name__ == '__main__':
    try:
        estreamer.crossprocesslogging.IsMultiProcess = False
        estreamer.crossprocesslogging._configure(
            'estreamer.log',
            estreamer.crossprocesslogging.INFO,
            '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
            False,
            False )

        Configure().cli()

    except Exception as ex:
        sys.exit( definitions.EXIT_ERROR_CODE )
