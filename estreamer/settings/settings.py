
#********************************************************************
#      File:    settings.py
#      Author:  Sam Strachan
#
#      Description:
#       Settings is the programmatic representation of whatever is
#       in the configuration file. It provides context to all processes
#       within the service
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

import estreamer
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
import estreamer.streams

from estreamer.adapters.base64 import dumps as base64dump
from estreamer.settings.logging import LoggingSettings
from estreamer.settings.monitor import MonitorSettings
from estreamer.settings.outputter import OutputterSettings

#pylint: disable=E1101

class Settings( object ):
    """Class which encapsulates the config file and all other globally
    accessible settings"""
    def __init__( self, jsonSettings ):
        self._adapters = None
        self._streams = None
        self._cache = None
        self._bookmark = None

        self.osname = os.name
        self.store = jsonSettings

        # Keep these values as is unless debugging
        self.allowExitWithoutFlush = False
        self.reprocessPkcs12 = False

        if 'queueSize' in jsonSettings:
            self.queueSize = jsonSettings['queueSize']
        else:
            self.queueSize = 200

        if 'batchSize' in jsonSettings:
            self.batchSize = jsonSettings['batchSize']
        else:
            self.batchSize = 100

        if 'workerProcesses' in jsonSettings:
            self.workerProcesses = jsonSettings['workerProcesses']
        else:
            self.workerProcesses = 4

        # To be converted into server array
        server = jsonSettings['subscription']['servers'][0]
        self.host = server['host']
        self.port = server['port']
        self.tlsVersion = server['tlsVersion']
        self.pkcs12Filepath = server['pkcs12Filepath']

        self.connectTimeout = jsonSettings['connectTimeout']
        self.responseTimeout = jsonSettings['responseTimeout']
        self.start = jsonSettings['start']

        self.alwaysAttemptToContinue = False
        self.enabled = True
        self.conditions = []

        if 'alwaysAttemptToContinue' in jsonSettings:
            self.alwaysAttemptToContinue = jsonSettings['alwaysAttemptToContinue']

        if 'enabled' in jsonSettings:
            self.enabled = jsonSettings['enabled']

        if 'conditions' in jsonSettings:
            self.conditions = jsonSettings['conditions']


        if 'monitor' in jsonSettings:
            self.monitor = MonitorSettings( jsonSettings['monitor'] )
        else:
            self.monitor = MonitorSettings( None )

        if 'logging' in jsonSettings:
            self.logging = LoggingSettings( jsonSettings['logging'] )
        else:
            self.logging = LoggingSettings( None )

        subscriptionRecords = jsonSettings['subscription']['records']
        self.subscribePacketData = subscriptionRecords['packetData']
        self.subscribeExtended = subscriptionRecords['extended']
        self.subscribeMetaData = subscriptionRecords['metadata']
        self.subscribeEventExtraData = subscriptionRecords['eventExtraData']
        self.subscribeImpactEventAlerts = subscriptionRecords['impactEventAlerts']
        self.subscribeIntrusion = subscriptionRecords['intrusion']
        self.subscribeArchiveTimestamps = subscriptionRecords['archiveTimestamps']

        handlerRecords = jsonSettings['handler']['records']
        self.writeCore = handlerRecords['core']
        self.writeMetadata = handlerRecords['metadata']
        self.writeConnections = True
        if 'connections' in handlerRecords:
            self.writeConnections = handlerRecords['connections']

        self.writePackets = handlerRecords['packets']
        self.writeIntrusion = handlerRecords['intrusion']
        self.writeRua = handlerRecords['rua']
        self.writeRna = handlerRecords['rna']

        self.writeRecordTypes = handlerRecords['include']
        self.writeExcludeRecordTypes = handlerRecords['exclude']

        self.outputters = []

        self.decode = False
        for outputter in jsonSettings['handler']['outputters']:
            outputterSettings = OutputterSettings( outputter )
            if outputterSettings.enabled:
                self.outputters.append( outputterSettings )
                self.decode |= not outputterSettings.passthru

        self.version = Settings.__version()
        self.sha256 = estreamer.Hasher().hexdigest()



    @staticmethod
    def __version():
        if hasattr( estreamer, '__version__' ):
            return estreamer.__version__

        else:
            return 'development'



    @staticmethod
    def create( filepath ):
        """Creates a new settings object and initialises logging"""
        if not os.path.isfile( filepath ):
            raise estreamer.EncoreException(
                'Settings file: {0} does not exist or is not a file'.format(
                    filepath ))

        with open( filepath, 'r' ) as configFile:
            try:
                config = json.load( configFile )
                settings = Settings( config )
                return settings

            except ValueError:
                raise estreamer.ParsingException('Invalid JSON in settings file')



    def instanceFilename( self, name ):
        """Returns a file name specific to this configuration instance. Typically
        this will prefix the host and port to the filename"""
        return os.path.abspath( '{0}-{1}_{2}'.format( self.host, self.port, name ) )



    def privateKeyFilepath( self ):
        """Returns the private key filepath"""
        return self.instanceFilename('pkcs.key')



    def publicKeyFilepath( self ):
        """Returns the public key filepath"""
        return self.instanceFilename('pkcs.cert')



    def bookmarkFilepath( self ):
        """Returns the name of the bookmark file"""
        return self.instanceFilename('bookmark.dat')



    def cacheFilepath( self ):
        """Returns the name of the cache file"""
        return self.instanceFilename('cache.dat')



    def statusFilepath( self ):
        """Returns the name of the status file"""
        return self.instanceFilename('status.dat')



    def pidFilepath( self ):
        """Returns the name of the pid file"""
        return self.instanceFilename('proc.pid')



    def requestFlags( self ):
        """Turns config settings into request flags"""
        flagList = []

        if self.subscribePacketData:
            flagList.append( definitions.MESSAGE_REQUEST_PACKET_DATA )

        if self.subscribeImpactEventAlerts:
            flagList.append( definitions.MESSAGE_REQUEST_IMPACT )

        if self.subscribeIntrusion:
            flagList.append( definitions.MESSAGE_REQUEST_INTRUSION )

        if self.subscribeMetaData:
            flagList.append( definitions.MESSAGE_REQUEST_METADATA)

        if self.subscribeArchiveTimestamps:
            flagList.append( definitions.MESSAGE_REQUEST_ARCHIVE_TIMESTAMPS )

        if self.subscribeEventExtraData:
            flagList.append( definitions.MESSAGE_REQUEST_EVENT_EXTRA_DATA )

        if self.subscribeExtended:
            flagList.append( definitions.MESSAGE_REQUEST_EXTENDED )

        flags = 0

        for flag in flagList:
            flags |= flag

        return flags



    def initialTimestamp( self ):
        """Returns the initial timestamp"""
        logger = estreamer.crossprocesslogging.getLogger(
            self.__class__.__name__ )

        if self.start == 0:
            # Oldest data available
            logger.info('Timestamp: Start = 0 (Oldest data available)')
            return definitions.TIMESTAMP_GENESIS

        elif self.start == 1:
            # Now
            logger.info('Timestamp: Start = 1 (Current data)')
            return definitions.TIMESTAMP_NOW

        else:
            # Bookmark
            bookmark = estreamer.Bookmark( self.bookmarkFilepath() )
            timeInt = bookmark.read()
            logger.info('Timestamp: Start = 2 (Bookmark = {0})'.format( timeInt ))
            return timeInt



    def adapters( self ):
        if self._adapters is None:
            self._adapters = []
            for settingsOutputter in self.outputters:
                try:
                    adapter = __import__(
                        'estreamer.adapters.{0}'.format( settingsOutputter.adapter ),
                        fromlist = ['estreamer.adapters'] )

                    self._adapters.append( adapter )

                except ImportError:
                    raise estreamer.EncoreException(
                        'Unrecognised adapter: {0}'.format( settingsOutputter.adapter ))

        return self._adapters



    def streams( self ):
        if self._streams is None:
            self._streams = []
            for settingsOutputter in self.outputters:
                stream = estreamer.streams.create( settingsOutputter.stream )
                self._streams.append( stream )

        return self._streams



    def cache( self ):
        if self._cache is None:
            self._cache = estreamer.metadata.Cache( self.cacheFilepath() )
            self._cache.load()

        return self._cache



    def bookmark( self ):
        if self._bookmark is None:
            self._bookmark = estreamer.Bookmark( self.bookmarkFilepath() )

        return self._bookmark



    def close( self ):
        if self._cache:
            self._cache.save()

        if self._streams:
            for stream in self._streams:
                stream.close()



    def toBase64( self ):
        return base64dump( self.store )
