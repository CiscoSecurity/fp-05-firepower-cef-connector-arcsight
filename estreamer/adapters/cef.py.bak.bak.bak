
#********************************************************************
#      File:    cef.py
#      Author:  Sam Strachan
#
#      Description:
#       CEF adapter
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

import binascii
import copy
import time
import socket
import estreamer
import estreamer.adapters.kvpair
import estreamer.definitions as definitions
import estreamer.common
from estreamer.metadata import View


# Syslog settings
SYSLOG_FACILITY_USER   = 1
SYSLOG_PRIORITY_NOTICE = 5

# Calc and save the syslog numeric (do not change, gets calculated)
SYSLOG_NUMERIC = (SYSLOG_FACILITY_USER << 3  | SYSLOG_PRIORITY_NOTICE)

# CEF header field values
CEF_VERSION     = 0
CEF_DEV_VENDOR  = 'Cisco'
CEF_DEV_PRODUCT = 'Firepower'
CEF_DEV_VERSION = '6.0'

# Packet truncation length
PACKET_LENGTH_MAX = 1022

# Output encoding: ascii / utf8 or hex
PACKET_ENCODING = 'ascii'



def __severity( priority, impact ):
    matrix = {
        1: {  # High
            1: '10',
            2: '9',
            3: '7',
            4: '8',
            5: '9'
        },
        2: {  # Medium
            1: '7',
            2: '6',
            3: '4',
            4: '5',
            5: '6'
        },
        3: {  # Low
            1: '3',
            2: '2',
            3: '0',
            4: '1',
            5: '2'
        }
    }

    if priority in matrix and impact in matrix[priority]:
        return matrix[priority][impact]

    return 5



def __ipv4( ipAddress ):
    if ipAddress.startswith('::ffff:'):
        return ipAddress[7:]

    elif ipAddress.find(':') == -1:
        return ipAddress

    return ''



def __ipv6( ipAddress ):
    if ipAddress == '::':
        return ''

    elif ipAddress.startswith('::ffff:'):
        return ''

    elif ipAddress.find(':') > -1:
        return ipAddress

    return ''



def __packetData( data ):
    payload = ''
    packet = estreamer.common.Packet.createFromHex( data )

    if PACKET_ENCODING == 'ascii':
        payload = packet.getPayloadAsAscii()

    elif PACKET_ENCODING == 'utf8':
        payload = packet.getPayloadAsUtf8()

    elif PACKET_ENCODING == 'hex':
        payload = packet.getPayloadAsHex()

    else:
        raise estreamer.EncoreException( 'Unknown packet encoding' )

    return payload[ 0 : PACKET_LENGTH_MAX ]



MAPPING = {
    # 2
    definitions.RECORD_PACKET: {
        'sig_id': lambda rec: 'PKT:2:1',

        'name': lambda rec: 'Packet Data',

        'severity': lambda rec: 7,

        'constants': {
            'cs1Label': 'payload',
        },

        'lambdas': {
            'rt': lambda rec: rec['eventSecond'] * 1000,
            'start': lambda rec: rec['packetSecond'] * 1000,
            'deviceExternalId': lambda rec: rec['deviceId'],
            'cs1': lambda rec: __packetData( rec['packetData'] )
        },

        'fields': {
            'deviceId': 'dvchost',
            'eventId': 'externalId'
        },

        'viewdata': {
            View.SENSOR: 'dvchost'
        },
    },

    # 71
    definitions.RECORD_RNA_CONNECTION_STATISTICS: {
        'sig_id': lambda rec: 'RNA:1003:1',

        'name': lambda rec: 'CONNECTION STATISTICS',

        'severity': lambda rec: 3 if rec['ruleAction'] < 4 else 7,

        'constants': {
            'cs1Label': 'fwPolicy',
            'cs2Label': 'fwRule',
            'cs3Label': 'ingressZone',
            'cs4Label': 'egressZone',
            'cs5Label': 'secIntelCategory'
        },

        'lambdas': {
            'rt': lambda rec: rec['firstPacketTimestamp'] * 1000,
            'start': lambda rec: rec['firstPacketTimestamp'] * 1000,
            'end': lambda rec: rec['lastPacketTimestamp'] * 1000,
            'src': lambda rec: __ipv4( rec['initiatorIpAddress'] ),
            'dst': lambda rec: __ipv4( rec['responderIpAddress'] ),
            'c6a2': lambda rec: __ipv6( rec['initiatorIpAddress'] ),
            'c6a3': lambda rec: __ipv6( rec['responderIpAddress'] ),
            'deviceExternalId': lambda rec: rec['deviceId'],
        },

        'fields': {
            'deviceId': 'dvchost',
            'ingressZone': 'cs3',
            'egressZone': 'cs4',
            'ingressInterface': 'deviceInboundInterface',
            'egressInterface': 'deviceOutboundInterface',
            'initiatorIpAddress': '',
            'responderIpAddress': '',
            'originalClientIpAddress': '',
            'policyRevision': 'cs1',
            'ruleId': 'cs2',
            'tunnelRuleId': '',
            'ruleAction': 'act',
            'ruleReason': 'reason',
            'initiatorPort': 'spt',
            'responderPort': 'dpt',
            'tcpFlags': '',
            'protocol': 'proto',
            'netflowSource': '',
            'instanceId': 'dvcpid',
            'connectionCounter': 'externalId',
            'firstPacketTimestamp': '', # Used to generate rt and start
            'lastPacketTimestamp': '', # Used to generate end
            'initiatorTransmittedPackets': '',
            'responderTransmittedPackets': '',
            'initiatorTransmittedBytes': 'bytesOut',
            'responderTransmittedBytes': 'bytesIn',
            'initiatorPacketsDropped': '',
            'responderPacketsDropped': '',
            'initiatorBytesDropped': '',
            'responderBytesDropped': '',
            'qosAppliedInterface': '',
            'qosRuleId': '',
            'userId': 'suser',
            'applicationId': 'app',
            'urlCategory': '',
            'urlReputation': '',
            'clientApplicationId': 'requestClientApplication',
            'webApplicationId': '',
            'clientUrl.data': 'request',
            'netbios': '',
            'clientApplicationVersion': '',
            'monitorRules1': '',
            'monitorRules2': '',
            'monitorRules3': '',
            'monitorRules4': '',
            'monitorRules5': '',
            'monitorRules6': '',
            'monitorRules7': '',
            'monitorRules8': '',
            'securityIntelligenceSourceDestination': '',
            'securityIntelligenceLayer': '',
            'fileEventCount': '',
            'intrusionEventCount': '',
            'initiatorCountry': '',
            'responderCountry': '',
            'originalClientCountry': '',
            'iocNumber': '',
            'sourceAutonomousSystem': '',
            'destinationAutonomousSystem': '',
            'snmpIn': '',
            'snmpOut': '',
            'sourceTos': '',
            'destinationTos': '',
            'sourceMask': '',
            'destinationMask': '',
            'securityContext': '',
            'vlanId': '',
            'referencedHost': '',
            'userAgent': '',
            'httpReferrer': '',
            'sslCertificateFingerprint': '',
            'sslPolicyId': '',
            'sslRuleId': '',
            'sslCipherSuite': '',
            'sslVersion': '',
            'sslServerCertificateStatus': '',
            'sslActualAction': '',
            'sslExpectedAction': '',
            'sslFlowStatus': '',
            'sslFlowError': '',
            'sslFlowMessages': '',
            'sslFlowFlags': '',
            'sslServerName': '',
            'sslUrlCategory': '',
            'sslSessionId': '',
            'sslSessionIdLength': '',
            'sslTicketId': '',
            'sslTicketIdLength': '',
            'networkAnalysisPolicyRevision': '',
            'endpointProfileId': '',
            'securityGroupId': '',
            'locationIpv6': '',
            'httpResponse': '',
            'dnsQuery.data': 'destinationDnsDomain',
            'dnsRecordType': '',
            'dnsResponseType': '',
            'dnsTtl': '',
            'sinkholeUuid': '',
            'securityIntelligenceList1': 'cs5',
            'securityIntelligenceList2': ''
        },

        'viewdata': {
            View.SENSOR: 'dvchost',
            View.SEC_ZONE_INGRESS: 'cs3',
            View.SEC_ZONE_EGRESS: 'cs4',
            View.SEC_INTEL_LIST1: 'cs5',
            View.IFACE_INGRESS: 'deviceInboundInterface',
            View.IFACE_EGRESS: 'deviceOutboundInterface',
            View.FW_POLICY: 'cs1',
            View.FW_RULE: 'cs2',
            View.FW_RULE_ACTION: 'act',
            View.FW_RULE_REASON: 'reason',
            View.PROTOCOL: 'proto',
            View.USER: 'suser',
            View.APP_PROTO: 'app',
            View.CLIENT_APP: 'requestClientApplication',
        },
    },

    # 112
    definitions.RECORD_CORRELATION_EVENT: {
        'sig_id': lambda rec: 'PV:112:{0}:{1}'.format(
            rec['ruleId'],
            rec['policyId']
        ),

        'name': lambda rec: 'POLICY VIOLATION',

        'severity': lambda rec: __severity(
            rec['priority'],
            rec['{0}.{1}'.format( View.OUTPUT_KEY,View.IMPACT )] ),

        'constants': {
            'cs1Label': 'policy',
            'cs2Label': 'policyRule',
            'cs3Label': 'ingressZone',
            'cs4Label': 'egressZone',
            'cn1Label': 'vlan'
            #'cn2Label': 'impact'
        },

        'lambdas': {
            'rt': lambda rec: rec['correlationEventSecond'] * 1000,
            'src': lambda rec: __ipv4( rec['sourceIpv6Address'] ),
            'dst': lambda rec: __ipv4( rec['destinationIpv6Address'] ),
            'c6a2': lambda rec: __ipv6( rec['sourceIpv6Address'] ),
            'c6a3': lambda rec: __ipv6( rec['destinationIpv6Address'] ),
        },

        'fields': {
            'deviceId': 'deviceExternalId',
            'correlationEventSecond': '', # Used to generate rt
            'eventId': 'externalId',
            'policyId': 'cs1',
            'ruleId': 'cs2',
            'priority': '', # Used to generate severity
            'eventDescription.data': 'msg',
            'eventType': '',
            'eventDeviceId': 'dvchost',
            'signatureId': '',
            'signatureGeneratorId': '',
            'triggerEventSecond': '',
            'triggerEventMicrosecond': '',
            'deviceEventId': '',
            'eventDefinedMask': '',
            'eventImpactFlags': '', # Used to generate severity
            'ipProtocol': 'proto',
            'networkProtocol': '',
            'sourceIp': '',
            'sourceHostType': '',
            'sourceVlanId': 'cn1',
            'sourceOperatingSystemFingerprintUuid': '',
            'sourceCriticality': '',
            'sourceUserId': 'suser',
            'sourcePort': 'spt',
            'sourceServerId': '',
            'destinationIp': '',
            'destinationHostType': '',
            'destinationVlanId': '',
            'destinationOperatingSystemFingerprintUuid': '',
            'destinationCriticality': '',
            'destinationUserId': 'duser',
            'destinationPort': 'dpt',
            'destinationServerId': '',
            'blocked': 'act',
            'ingressIntefaceUuid': 'deviceInboundInterface',
            'egressIntefaceUuid': 'deviceOutboundInterface',
            'ingressZoneUuid': 'cs3',
            'egressZoneUuid': 'cs4',
            'sourceIpv6Address': '',
            'destinationIpv6Address': '',
            'sourceCountry': '',
            'destinationCountry': '',
            'securityIntelligenceUuid': '',
            'securityContext': '',
            'sslPolicyId': '',
            'sslRuleId': '',
            'sslActualAction': '',
            'sslFlowStatus': '',
            'sslCertificateFingerprint': '',
        },

        'viewdata': {
            View.SENSOR: 'dvchost',
            View.CORRELATION_POLICY: 'cs1',
            View.CORRELATION_RULE: 'cs2',
            View.BLOCKED: 'act',
            View.PROTOCOL: 'proto',
            View.APP_PROTO: 'app',
            View.SOURCE_USER: 'suser',
            View.DESTINATION_USER: 'duser',
            View.IFACE_INGRESS: 'deviceInboundInterface',
            View.IFACE_EGRESS: 'deviceOutboundInterface',
            View.SEC_ZONE_INGRESS: 'cs3',
            View.SEC_ZONE_EGRESS: 'cs4'
            #View.IMPACT: 'cn2',
        },
    },

    # 125
    definitions.RECORD_MALWARE_EVENT: {
        'sig_id': lambda rec: 'FireAMP:125:1',

        'name': lambda rec: 'FireAMP Event',

        'severity': lambda rec: rec['threatScore'] / 10,

        'constants': {
            'cs1Label': 'policy',
            'cs2Label': 'virusName',
            'cs3Label': 'disposition',
            'cs4Label': 'speroDisposition',
            'cs5Label': 'eventDescription',
        },

        'lambdas': {
            'rt': lambda rec: rec['malwareEventTimestamp'] * 1000,
            'start': lambda rec: rec['connectionEventTimestamp'] * 1000,
            'src': lambda rec: __ipv4( rec['sourceIpAddress'] ),
            'dst': lambda rec: __ipv4( rec['destinationIpAddress'] ),
            'c6a2': lambda rec: __ipv6( rec['sourceIpAddress'] ),
            'c6a3': lambda rec: __ipv6( rec['destinationIpAddress'] ),
            'deviceExternalId': lambda rec: rec['deviceId'],
        },

        'viewdata': {
            View.SENSOR: 'dvchost',
            View.PROTOCOL: 'proto',
            View.USER: 'suser',
            View.APP_PROTO: 'app',
            View.CLIENT_APP: 'requestClientApplication',
            View.MALWARE_EVENT_TYPE: 'outcome',
            View.FILE_TYPE: 'fileType',
            View.AGENT_USER: 'duser',
            View.FILE_POLICY: 'cs1',
            View.DETECTION_NAME: 'cs2',
            View.DISPOSITION: 'cs3',
            View.RETRO_DISPOSITION: 'cs4',
        },

        'fields': {
            'agentUuid': '',
            'cloudUuid': '',
            'malwareEventTimestamp': '', # Used to generate rt
            'eventTypeId': 'outcome',
            'eventSubtypeId': '',
            'detectorId': '',
            'detectionName.data': 'cs2',
            'user.data': 'suser',
            'fileName.data': 'fname',
            'filePath.data': 'filePath',
            'fileShaHash.data': 'fileHash',
            'fileSize': 'fsize',
            'fileType': 'fileType',
            'fileTimestamp': 'fileCreateTime',
            'parentFileName.data': 'sproc',
            'parentShaHash': '',
            'eventDescription.data': 'cs5',
            'deviceId': 'dvchost',
            'connectionInstance': 'dvcpid',
            'connectionCounter': '',
            'connectionEventTimestamp': '', # Used to generate start
            'direction': 'deviceDirection',
            'sourceIpAddress': '',
            'destinationIpAddress': '',
            'applicationId': 'app',
            'userId': 'duser',
            'accessControlPolicyUuid': 'cs1',
            'disposition': 'cs3',
            'retroDisposition': 'cs4',
            'uri.data': 'request',
            'sourcePort': 'spt',
            'destinationPort': 'dpt',
            'sourceCountry': '',
            'destinationCountry': '',
            'webApplicationId': '',
            'clientApplicationId': 'requestClientApplication',
            'action': 'act',
            'protocol': 'proto',
            'threatScore': '',
            'iocNumber': '',
            'securityContext': '',
            'sslCertificateFingerprint': '',
            'sslActualAction': '',
            'sslFlowStatus': '',
            'archiveSha': '',
            'archiveName': '',
            'archiveDepth': '',
            'httpResponse': '',
        },
    },

    # 400
    definitions.RECORD_INTRUSION_EVENT: {
        'sig_id': lambda rec: '[{0}:{1}]'.format(
            rec['generatorId'],
            rec['@computed.renderedId']
        ),

        'name': lambda rec: rec['@computed.message'],

        'severity': lambda rec: __severity(
            rec['priorityId'],
            rec['impact'] ),

        'constants': {
            'cs1Label': 'fwPolicy',
            'cs2Label': 'fwRule',
            'cs3Label': 'ingressZone',
            'cs4Label': 'egressZone',
            'cs5Label': 'ipsPolicy',
            'cs6Label': 'ruleId',
            'cn1Label': 'vlan',
            'cn2Label': 'impact',
        },

        'lambdas': {
            'rt': lambda rec: rec['eventSecond'] * 1000,
            'start': lambda rec: rec['connectionTimestamp'] * 1000,
            'src': lambda rec: __ipv4( rec['sourceIpAddress'] ),
            'dst': lambda rec: __ipv4( rec['destinationIpAddress'] ),
            'c6a2': lambda rec: __ipv6( rec['sourceIpAddress'] ),
            'c6a3': lambda rec: __ipv6( rec['destinationIpAddress'] ),
            'deviceExternalId': lambda rec: rec['deviceId'],
            'request': lambda rec: '',
            'act': lambda rec: ['Alerted', 'Blocked', 'Would Be Blocked'][ rec['blocked'] ]
        },

        'viewdata': {
            View.SENSOR: 'dvchost',
            View.CLASSIFICATION_DESCRIPTION: 'cat',
            View.IP_PROTOCOL: 'proto',
            View.IDS_POLICY: 'cs5',
            View.RENDERED_ID: 'cs6',
            View.USER: 'suser',
            View.CLIENT_APP: 'requestClientApplication',
            View.APP_PROTO: 'app',
            View.FW_POLICY: 'cs1',
            View.FW_RULE: 'cs2',
            View.IFACE_INGRESS: 'deviceInboundInterface',
            View.IFACE_EGRESS: 'deviceOutboundInterface',
            View.SEC_ZONE_INGRESS: 'cs3',
            View.SEC_ZONE_EGRESS: 'cs4'
        },

        'fields': {
            'deviceId': 'dvchost',
            'eventId': 'externalId',
            'eventSecond': '', # Used to generate rt
            'eventMicrosecond': '',
            'renderedId': 'cs6', # Used to generate sig_id
            'generatorId': '', # Used to generate sig_id
            'ruleRevision': '',
            'classificationId': 'cat',
            'priorityId': '', # Used to generate severity
            'sourceIpAddress': '',
            'destinationIpAddress': '',
            'sourcePortOrIcmpType': 'spt',
            'destinationPortOrIcmpType': 'dpt',
            'ipProtocolId': 'proto',
            'impactFlags': '',
            'impact': 'cn2', # Used to generate severity
            'blocked': 'act',
            'mplsLabel': '',
            'vlanId': 'cn1',
            'pad': '',
            'policyUuid': 'cs5',
            'userId': 'suser',
            'webApplicationId': '',
            'clientApplicationId': 'requestClientApplication',
            'applicationId': 'app',
            'accessControlRuleId': 'cs2',
            'accessControlPolicyUuid': 'cs1',
            'interfaceIngressUuid': 'deviceInboundInterface',
            'interfaceEgressUuid': 'deviceOutboundInterface',
            'securityZoneIngressUuid': 'cs3',
            'securityZoneEgressUuid': 'cs4',
            'connectionTimestamp': '', # Used to generate start
            'connectionInstanceId': 'dvcpid',
            'connectionCounter': '',
            'sourceCountry': '',
            'destinationCountry': '',
            'iocNumber': '',
            'securityContext': '',
            'sslCertificateFingerprint': '',
            'sslActualAction': '',
            'sslFlowStatus': '',
            'networkAnalysisPolicyUuid': '',
            'httpResponse': '',
        },
    },

    # 500 (and also 502 - it's copied below)
    definitions.RECORD_FILELOG_EVENT: {
        'sig_id': lambda rec: 'File:500:1',

        'name': lambda rec: '{0}'.format( rec['@computed.recordTypeDescription'] ),

        'severity': lambda rec: rec['threatScore'] / 10,

        'constants': {
            'cs1Label': 'filePolicy',
            'cs2Label': 'disposition',
            'cs3Label': 'speroDisposition'
        },

        'lambdas': {
            'rt': lambda rec: rec['fileEventTimestamp'] * 1000,
            'start': lambda rec: rec['connectionTimestamp'] * 1000,
            'src': lambda rec: __ipv4( rec['sourceIpAddress'] ),
            'dst': lambda rec: __ipv4( rec['destinationIpAddress'] ),
            'c6a2': lambda rec: __ipv6( rec['sourceIpAddress'] ),
            'c6a3': lambda rec: __ipv6( rec['destinationIpAddress'] ),
            'deviceExternalId': lambda rec: rec['deviceId'],
        },

        'viewdata': {
            View.SENSOR: 'dvchost',
            View.DISPOSITION: 'cs2',
            View.SPERO_DISPOSITION: 'cs3',
            View.FILE_ACTION: 'act',
            View.FILE_TYPE: 'fileType',
            View.APP_PROTO: 'app',
            View.USER: 'suser',
            View.PROTOCOL: 'proto',
            View.FILE_POLICY: 'cs1',
            View.CLIENT_APP: 'requestClientApplication',
        },

        'fields': {
            'deviceId': 'dvchost',
            'connectionInstance': 'dvcpid',
            'connectionCounter': '',
            'connectionTimestamp': '', # Used to generate start
            'fileEventTimestamp': '', # Used to generate rt
            'sourceIpAddress': '',
            'destinationIpAddress': '',
            'disposition': 'cs2',
            'speroDisposition': 'cs3',
            'fileStorageStatus': '',
            'fileAnalysisStatus': '',
            'localMalwareAnalysisStatus': '',
            'archiveFileStatus': '',
            'threatScore': '', # Used to generate severity
            'action': 'act',
            'shaHash': 'fileHash',
            'fileTypeId': 'fileType',
            'fileName.data': 'fname',
            'fileSize': 'fsize',
            'direction': 'deviceDirection',
            'applicationId': 'app',
            'userId': 'suser',
            'uri.data': 'request',
            'signature.data': 'cs4',
            'sourcePort': 'spt',
            'destinationPort': 'dpt',
            'protocol': 'proto',
            'accessControlPolicyUuid': 'cs1',
            'sourceCountry': '',
            'destinationCountry': '',
            'webApplicationId': '',
            'clientApplicationId': 'requestClientApplication',
            'securityContext': '',
            'sslCertificateFingerprint': '',
            'sslActualAction': '',
            'sslFlowStatus': '',
            'archiveSha': '',
            'archiveName': '',
            'archiveDepth': '',
        },
    },
}

# 502
MAPPING[ definitions.RECORD_FILELOG_MALWARE_EVENT ] = copy.deepcopy(
    MAPPING[ definitions.RECORD_FILELOG_EVENT ])

MAPPING[ definitions.RECORD_FILELOG_MALWARE_EVENT ]['sig_id'] = lambda rec: 'FileMalware:502:1'



class Cef( object ):
    """Cef adapter class to contain implementation"""
    def __init__( self, source ):
        self.source = source
        self.record = estreamer.common.Flatdict( source, True )
        self.output = None
        self.mapping = None

        if 'recordType' in self.record:
            if self.record['recordType'] in MAPPING:
                self.mapping = MAPPING[ self.record['recordType'] ]
                self.output = {}



    @staticmethod
    def __sanitize( value ):
        """Escapes invalid characters"""
        if not isinstance( value, basestring ):
            value = str( value )

        # Escape \ " ]
        value = value.replace('\\', '\\\\')
        value = value.replace('"', '\\"')
        value = value.replace(']', '\\]')

        return value



    def __convert( self ):
        """Writes the self.output dictionary"""

        # Do the fields first (mapping)
        for source in self.mapping['fields']:
            target = self.mapping['fields'][source]
            if len(target) > 0:
                self.output[target] = self.record[source]

        # Now the constants (hard coded values)
        for target in self.mapping['constants']:
            self.output[target] = self.mapping['constants'][target]

        # Lambdas
        for target in self.mapping['lambdas']:
            function = self.mapping['lambdas'][target]
            self.output[target] = function( self.record )

        # View data last
        for source in self.mapping['viewdata']:
            key = '{0}.{1}'.format( View.OUTPUT_KEY, source )
            value = self.record[key]
            if value is not None:
                target = self.mapping['viewdata'][source]
                self.output[target] = value

        keys = self.output.keys()
        for key in keys:
            if isinstance( self.output[ key ], basestring) and len( self.output[ key ] ) == 0:
                del self.output[ key ]

            elif self.output[ key ] == 0:
                del self.output[ key ]

            else:
                self.output[ key ] = Cef.__sanitize( self.output[ key ] )



    def __cefMessage( self ):
        """Takes a transformed dictionary and converts it to a CEF message"""
        # my ($sig_id, $name, $severity, $message) = @_;

        # my $hostname = hostname();
        # $hostname =~ s/\.+$//;
        hostname = socket.gethostname()

        # http://search.cpan.org/~dexter/POSIX-strftime-GNU-0.02/lib/POSIX/strftime/GNU.pm
        # # Get syslog-style timestamp: MAR  1 16:23:11
        # my $datetime = strftime('%b %e %T', localtime(time()));
        now = time.strftime('%b %d %X')

        # Key value pairs
        data = estreamer.adapters.kvpair.dumps(
            self.output,
            delimiter = ' ',
            quoteSpaces = False,
            sort = True )

        # Special fields
        sigId = self.mapping['sig_id']( self.record )
        name = self.mapping['name']( self.record )
        severity = self.mapping['severity']( self.record )

        # my $cef_message = "CEF:$CEF_VERSION|$CEF_DEV_VENDOR|$CEF_DEV_PRODUCT|
        # ...$CEF_DEV_VERSION|$sig_id|$name|$severity|$message";
        # # Update the message with the details
        # $message = "<$SYSLOG_NUMERIC>$datetime $hostname $cef_message";
        message = u'<{8}>{9} {10} CEF:{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}'.format(
            CEF_VERSION,
            CEF_DEV_VENDOR,
            CEF_DEV_PRODUCT,
            CEF_DEV_VERSION,
            sigId,
            name.replace('|','\|'),
            severity,
            data,
            SYSLOG_NUMERIC,
            now,
            hostname
        )

        return message



    def dumps( self ):
        """Dumps the current record to a CEF message (or None)"""
        if self.mapping is None:
            return None

        self.__convert()
        message = self.__cefMessage()

        return message



def dumps( source ):
    """Converts a source record into a CEF message"""
    cefAdapter = Cef( source )
    return cefAdapter.dumps()
