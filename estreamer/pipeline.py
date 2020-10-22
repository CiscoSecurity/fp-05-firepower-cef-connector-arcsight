"""
The pipeline module contains wrapper functions and classes for each of the
stages in the eNcore pipeline. Namely:
  * Receiving (getting data from eStreamer)
  * Parsing (Binary -> dict)
  * Decorating (Caching and reading metadata)
  * Transforming (serialising to output format)
  * Writing (Transport; to disk / network etc)
"""
#********************************************************************
#      File:    pipeline.py
#      Author:  Sam Strachan
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

import estreamer
import estreamer.definitions as definitions
import estreamer.crossprocesslogging as logging

from estreamer.adapters.binary import Binary
from estreamer.metadata import View
from estreamer.baseproc import QueueProcess
from estreamer.baseproc import BatchQueueProcess
from estreamer.receiver import Receiver

#pylint: disable=R0913,W0703

def _shouldParse( record, settings ):
    """
    Decides if a record should be decoded. This will mostly look at whether or not
    we need to write the record on the basis of its recordType, however, metadata
    records should always be decoded since we need to write them into our cache.

    The main reason for this check is performance. Parsing is expensive and we can
    save significant time here for certain records. we also do a check after this
    too to see if the user wants us to decode.
    """
    recordTypeId = 0
    if 'recordType' in record:
        recordTypeId = record['recordType']

    if recordTypeId == 0:
        return False

    if recordTypeId not in definitions.RECORDS:
        raise estreamer.EncoreException(
            'Record type {0} is unknown : not in scope'.format( recordTypeId ))

    result = False

    if recordTypeId in definitions.TYPES['CONNECTION']:
        if settings.writeConnections:
            result = True

    elif recordTypeId in definitions.TYPES['RNA']:
        if settings.writeRna:
            result = True

    elif recordTypeId in definitions.TYPES['RUA']:
        if settings.writeRua:
            result = True

    elif recordTypeId in definitions.TYPES['METADATA']:
        result = True

    elif recordTypeId in definitions.TYPES['PACKET']:
        if settings.writePackets:
            result = True

    elif recordTypeId in definitions.TYPES['INTRUSION']:
        if settings.writeIntrusion:
            result = True

    elif recordTypeId in definitions.TYPES['FILE_MALWARE'] or \
            recordTypeId in definitions.TYPES['CORRELATION'] or \
            recordTypeId in definitions.TYPES['EVENT']:
        if settings.writeCore:
            result = True

    # Regardless of above
    if recordTypeId in settings.writeRecordTypes:
        result = True

    if recordTypeId in settings.writeExcludeRecordTypes:
        result = False

    return result



def _shouldOutput( record, settings ):
    """
    If a record has made it this far, then it almost certainly wants to be
    written to output. The one exception to this is metadata, which may not be
    wanted but which we always need to parse for decorating.
    """
    if record['recordType'] in definitions.TYPES['METADATA']:
        return settings.writeMetadata

    return True



def parse( message, settings ):
    """
    Takes a message and returns a pipeline event
    {
        'bookmark': 1500145643,
        'message': {
            'version': 1,
            'messageType': 4,
            'length': 42,
            'data': '<binary>',
            'sequence': 4356
        },
        'record': {
            'recordType': 400,
            ...
        }
    }
    """
    event = {
        'bookmark': -1,
        'message': message,
        'record': None
    }

    try:
        parser = Binary( message )
        if _shouldParse( parser.record, settings ):
            parser.parse()

            if 'archiveTimestamp' in parser.record:
                event['bookmark'] = parser.record['archiveTimestamp']

            # Setting event['record'] means that we want to process, decorate and
            # output this event. If it is not set then the event will ultimately
            # be thrown away - but see below regarding sequencing.
            event['record'] = parser.record

    except estreamer.EncoreException as ex:
        # We want to catch EncoreExceptions here. Left to propagate further up
        # the stack, this will potentially impacts hundreds of messages in a
        # batched queue. EncoreExceptions are not ideal here, but they're far
        # from FATAL. So warn and carry on.
        logger = logging.getLogger( __name__ )
        logger.warning( ex )
        encodedMessage = estreamer.adapters.base64.dumps( message )
        logger.warning( 'Additional data: {0}'.format( encodedMessage ) )

    except Exception as ex:
        # If an error has occurred here, it's bad. It's most likely that the FMC
        # has sent us incorrect data - although could conceivably be a bad
        # message definition - although that will only be in development.
        #
        # In any case, if it's a bad message, then we need to file a defect with
        # the BU and ideally carry on. But log an error.
        logger = logging.getLogger( __name__ )
        logger.exception( ex )
        encodedMessage = estreamer.adapters.base64.dumps( message )
        logger.error( 'Additional data: {0}'.format( encodedMessage ) )

    # Always return the event even if we don't have a parsed record. The
    # message contains sequence numbers which are required for re-assembling
    # the correct order of events. Even if we ultimately throw this message
    # away, without it re-ordering cannot occur as too much information is lost.
    return event



def decorate( record, settings ):
    """
    Takes a record only, and decorates it
    """
    if settings.decode:
        # Update METADATA (this will only process certain record types)
        settings.cache().store( record )

        # Reads from METADATA and computes other things e.g. IP addrs
        record[ View.OUTPUT_KEY ] = estreamer.metadata.View(
            settings.cache(), record ).create()



def transform( event, settings ):
    """
    Takes a pipeline event and transforms it to pipeline event containing
    an array of payloads
    """
    adapters = settings.adapters()

    payloads = []
    for index in range( 0, len( adapters ) ):
        outputter = settings.outputters[ index ]

        if not outputter.passthru:
            output = adapters[ index ].dumps( event['record'] )

        else:
            output = adapters[ index ].dumps( event['message'] )

        payloads.append( output )

    return {
        'bookmark': event['bookmark'],
        'payloads': payloads
    }



def write( event, settings, delimiter = '\n' ):
    """
    Takes an event like:
    {
        'bookmark': 1234567890,
        'payloads': [
            'rec_type=400'
        ]
    }

    and writes it out to streams
    """
    streams = settings.streams()

    for index in range( 0, len( streams )):
        if not event['payloads'][ index ] is None:
            streams[ index ].write( event['payloads'][index] + delimiter )

    # Handle bookmarking
    if event['bookmark'] > -1:
        settings.bookmark().write( event['bookmark'] )

        # Only save if we've made a change
        settings.bookmark().save()



def parseDecorateTransformWrite( item, settings ):
    """
    Parses, decorates, transforms and writes
    """
    event = parse( item, settings )

    if event['record']:
        decorate( event['record'], settings )

        if _shouldOutput( event['record'], settings ):
            event = transform( event, settings )
            write( event, settings )



class Handler( QueueProcess ):
    """
    The Handler class takes a message and converts it to a record and places it
    in the outputQueue
    """
    def onEvent( self, item ):
        parseDecorateTransformWrite( item, self.settings )



class Subscriber( BatchQueueProcess ):
    """
    Subscriber opens a host connection and sends an Event Stream Request.
    It then handles responses accordingly - but in most cases putting them
    into the queue
    """
    def __init__( self, settings, parentPipe, logQueue, inputQueue, outputQueue ):
        self.receiver = Receiver( settings, logQueue, self.onEvent )
        self.receiver.init()
        super( Subscriber, self ).__init__(
            settings,
            parentPipe,
            logQueue,
            inputQueue,
            outputQueue )

    def onEvent( self, message ):
        self.count += 1
        self.sendOutput( message )

    def status( self ):
        stat = super( Subscriber, self ).status()
        stat['firstReceiveTime'] = self.receiver.connection.getFirstReceiveTime()
        stat['lastReceiveTime'] = self.receiver.connection.getLastReceiveTime(),
        return stat

    def start( self ):
        """
        Starts the subscription
        """
        try:
            self._start( self.receiver.next )

        except estreamer.ConnectionClosedException:
            self.logger.error( definitions.STRING_CONNECTION_CLOSED )

        self.logger.info('Exiting')



class Parser( BatchQueueProcess ):
    """
    The Parser class takes a message and converts it to a record and places it
    in the outputQueue
    """
    def onEvent( self, item ):
        event = parse( item, self.settings )
        self.sendOutput( event )



class Decorator( BatchQueueProcess ):
    """
    The Decorator class takes a message, adds metadata and sends it on to the
    transformers. The decorator, however, must receive messages in order. The
    problem is that the upstream binary parsing can happen in parallel - which
    will likely result in out-of-order delivery. Batching adds another layer of
    complexity. So we override onReceive to buffer and re-order
    """
    def __init__( self, settings, parentPipe, logQueue, inputQueue, outputQueue ):
        self.lastSequence = 0
        self.buffer = []
        super( Decorator, self ).__init__(
            settings,
            parentPipe,
            logQueue,
            inputQueue,
            outputQueue )

    def onEvent( self, item ):
        # We should only decorate and forward this message on if we have a
        # 'record' item - its presence indicates that we are interested in it
        if item['record']:
            decorate( item['record'], self.settings )
            if _shouldOutput( item['record'], self.settings ):
                self.sendOutput( item )

    def onReceive( self, items ):
        def _do( items ):
            for item in items:
                self.onEvent( item )
                self.count += 1
                self.lastSequence = item['message']['sequence']

        if items[0]['message']['sequence'] == self.lastSequence + 1:
            # These items are next in line to be processed
            _do( items )

            # Check to see if we have any buffered items
            while self.state == definitions.STATE_RUNNING and \
                  len( self.buffer ) > 0 and \
                  self.buffer[0][0]['message']['sequence'] == self.lastSequence + 1:

                self.logger.debug('Clearing sequence {0}; buffer: {1}'.format(
                    self.buffer[0][0]['message']['sequence'],
                    len( self.buffer ) ))

                _do( self.buffer[0] )
                del self.buffer[0]

                self._checkControlCommands()

        else:
            # These items are out-of-order. Stash them in our buffer
            self.buffer.append( items )

            self.logger.debug('Stashing sequence {0}; buffer: {1}'.format(
                items[0]['message']['sequence'],
                len( self.buffer ) ))

            if len( self.buffer ) % 1000 == 0:
                message = 'Out of order correction buffer length is growing: {0}'.format(
                    len( self.buffer ))
                self.logger.warning(message)

            # Keep the buffer sorted for future comparisons
            self.buffer.sort( key = lambda e: e[0]['message']['sequence'] )



class Transformer( BatchQueueProcess ):
    """
    The Transformer class takes a message and converts it to an array of
    messages expected by the Writer
    """
    def onEvent( self, item ):
        data = transform( item, self.settings )
        self.sendOutput( data )



class Writer( BatchQueueProcess ):
    """
    The Writer class takes a message and converts it to an array of
    messages expected for output
    """
    def status( self ):
        stat = super( Writer, self ).status()
        stat['bookmark'] = self.settings.bookmark().read()
        return stat

    def onEvent( self, item ):
        write( item, self.settings )



class Noop( BatchQueueProcess ):
    """
    The Noop class takes messages off one queue and puts it on the next
    """
    def onEvent( self, item ):
        self.sendOutput( item )



class SubscriberParser( Subscriber ):
    """
    Subscribes, parses and decorates events
    """
    def onEvent( self, message ):
        event = parse( message, self.settings )
        self.count += 1
        self.sendOutput( event )



class SubscriberParserDecorator( Subscriber ):
    """
    Subscribes, parses and decorates events
    """
    def onEvent( self, message ):
        event = parse( message, self.settings )
        if event['record']:
            decorate( event['record'], self.settings )
            self.count += 1

            if _shouldOutput( event['record'], self.settings ):
                self.sendOutput( event )



class TransformerWriter( Writer ):
    """
    Transforms and writes an event
    """
    def onEvent( self, item ):
        data = transform( item, self.settings )
        write( data, self.settings )



class SingleWorker( Subscriber ):
    """
    The Everything class takes a message and outputs it
    """
    def __init__( self, settings, parentPipe, logQueue, inputQueue, outputQueue ):
        super( SingleWorker, self ).__init__(
            settings,
            parentPipe,
            logQueue,
            inputQueue,
            outputQueue )

    def onEvent( self, message ):
        parseDecorateTransformWrite( message, self.settings )
        self.count += 1



class SynchronousSubscriber( Subscriber ):
    """
    Subscriber class which is designed to be run synchronously - no background
    process
    """
    def __init__( self, settings, logQueue, callback ):
        from multiprocessing import Pipe
        one = Pipe()[0]
        self._callback = callback
        super( SynchronousSubscriber, self ).__init__(
            settings,
            one,
            logQueue,
            None,
            None )

    def start( self ):
        pass

    def next( self ):
        """
        Triggers the next batch of messages which will fire an unknown but
        manageable number of onEvent()
        """
        try:
            self.receiver.next()

        except estreamer.ConnectionClosedException:
            self.logger.error( definitions.STRING_CONNECTION_CLOSED )

    def onEvent( self, message ):
        self._callback( message )
