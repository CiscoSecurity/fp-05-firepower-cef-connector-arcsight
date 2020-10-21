
#********************************************************************
#      File:    view.py
#      Author:  Sam Strachan
#
#      Description:
#       metadata.View contains all logic to do with adding additional
#       metadata to a given record.
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

import datetime
import re
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
from estreamer.adapters.binary import Binary
from estreamer.common import Flatdict
from estreamer.metadata.cache import Cache

class View( object ):
    """
    The view class adds derived, computed and cached metadata to the
    incoming wire record
    """
    OUTPUT_KEY = '@computed'


    ACTION = 'action'
    AGENT_USER = 'agentUser'
    APP_PROTO = 'applicationProtocol'
    ARCHIVE_FILE_STATUS = 'archiveFileStatus'
    BLOCKED = 'blocked'
    CLASSIFICATION_DESCRIPTION = 'classificationDescription'
    CLASSIFICATION_NAME = 'classificationName'
    CLIENT_APP = 'clientApplication'
    CLOUD = 'cloud'
    CORRELATION_RULE = 'correlationRule'
    CORRELATION_POLICY = 'correlationPolicy'
    DATA = 'data'
    DESCRIPTION = 'description'
    DESTINATION_APP_PROTO = 'destinationApplicationProtocol'
    DESTINATION_IP = 'destinationIp'
    DESTINATION_IP_COUNTRY = 'destinationIpCountry'
    DESTINATION_CRITICALITY = 'destinationCriticality'
    DESTINATION_HOSTTYPE = 'destinationHostType'
    DESTINATION_OS_NAME = 'destinationOperatingSystemName'
    DESTINATION_OS_VENDOR = 'destinationOperatingSystemVendor'
    DESTINATION_OS_VERSION = 'destinationOperatingSystemVersion'
    DESTINATION_USER = 'destinationUser'
    DETECTOR = 'detector'
    DETECTION = 'detection'
    DETECTION_NAME = 'detectionName'
    DIRECTION = 'direction'
    DISPOSITION = 'disposition'
    DNS_RECORD_NAME = 'dnsRecordName'
    DNS_RECORD_DESCRIPTION = 'dnsRecordDescription'
    DNS_RESPONSE_NAME = 'dnsResponseName'
    DNS_RESPONSE_DESCRIPTION = 'dnsResponseDescription'
    EVENT_DESC = 'eventDescription'
    EVENT_SEC = 'eventSecond'
    EVENT_TYPE = 'eventType'
    EVENT_USEC = 'eventMicrosecond'
    EVENT_TIMESTAMP = 'eventDateTime'
    FILE_ACTION = 'fileAction'
    FILE_ANALYSIS_STATUS = 'fileAnalysisStatus'
    FILE_POLICY = 'filePolicy'
    FILE_STORAGE_STATUS = 'fileStorageStatus'
    FILE_SANDBOX_STATUS = 'fileSandboxStatus'
    FILE_TYPE = 'fileType'
    FW_POLICY = 'firewallPolicy'
    FW_RULE = 'firewallRule'
    FW_RULE_ACTION = 'firewallRuleAction'
    FW_RULE_REASON = 'firewallRuleReason'
    IDS_POLICY = 'idsPolicy'
    IFACE_INGRESS = 'ingressInterface'
    IFACE_EGRESS = 'egressInterface'
    IMPACT = 'impact'
    IMPACT_DESCRIPTION = 'impactDescription'
    IOC_CATEGORY = 'iocCategory'
    IP_PROTOCOL = 'transportProtocol'
    MALWARE_ANALYSIS_STATUS = 'malwareAnalysisStatus'
    MALWARE_EVENT_TYPE = 'malwareEventType'
    MALWARE_EVENT_SUBTYPE = 'malwareEventSubtype'
    MONITOR_RULE = 'monitorRule{0}'
    MSG = 'message'
    NET_PROTO = 'networkProtocol'
    NETWORK_ANALYSIS_POLICY = 'networkAnalysisPolicy'
    ORIGINAL_CLIENT_SRC_IP = 'originalClientSrcIp'
    PARENT_DETECTION = 'parentDetection'
    PRIORITY = 'priority'
    PROTOCOL = 'protocol'
    REALM = 'realm'
    REC_TYPE_DESCRIPTION = 'recordTypeDescription'
    REC_TYPE_SIMPLE = 'recordTypeCategory'
    RENDERED_ID = 'renderedId'
    RETRO_DISPOSITION = 'retroDisposition'
    SEC_INTEL_EVENT = 'securityIntelligenceEvent'
    SEC_INTEL_IP = 'securityIntelligenceIp'
    SEC_INTEL_LIST1 = 'securityIntelligenceList1'
    SEC_INTEL_LIST2 = 'securityIntelligenceList2'
    SEC_INTEL_POLICY = 'securityIntelligencePolicy'
    SEC_ZONE_INGRESS = 'ingressSecurityZone'
    SEC_ZONE_EGRESS = 'egressSecurityZone'
    SECURITY_GROUP = 'securityGroup'
    SENSOR = 'sensor'
    SINKHOLE = 'sinkhole'
    SOURCE = 'source'
    SOURCE_APP_PROTO = 'sourceApplicationProtocol'
    SOURCE_IP = 'sourceIp'
    SOURCE_IP_COUNTRY = 'sourceIpCountry'
    SOURCE_CRITICALITY = 'sourceCriticality'
    SOURCE_HOSTTYPE = 'sourceHostType'
    SOURCE_TYPE = 'sourceType'
    SOURCE_OS_NAME = 'sourceOperatingSystemName'
    SOURCE_OS_VENDOR = 'sourceOperatingSystemVendor'
    SOURCE_OS_VERSION = 'sourceOperatingSystemVersion'
    SOURCE_USER = 'sourceUser'
    SPERO_DISPOSITION = 'speroDisposition'
    SSL_ACTUAL_ACTION = 'sslActualAction'
    SSL_CIPHER_SUITE = 'sslCipherSuite'
    SSL_EXPECTED_ACTION = 'sslExpectedAction'
    SSL_FLOW_FLAGS = 'sslFlowFlags'
    SSL_FLOW_MESSAGES = 'sslFlowMessages'
    SSL_FLOW_STATUS = 'sslFlowStatus'
    SSL_SERVER_CERT_STATUS = 'sslServerCertificateStatus'
    SSL_URL_CATEGORY = 'sslUrlCategory'
    SSL_VERSION = 'sslVersion'
    SUBTYPE = 'subtype'
    TYPE = 'type'
    UNHANDLED = 'unhandled'
    URL_CATEGORY = 'urlCategory'
    URL_REPUTATION = 'urlReputation'
    USER = 'user'
    WEB_APP = 'webApplication'



    AUTOMAP = {
        # 13
        definitions.RECORD_RNA_NEW_NET_PROTOCOL: [
            {
                'cache': Cache.NET_PROTOS,
                'id': 'networkProtocol',
                'view': NET_PROTO
            }
        ],

        # 14
        definitions.RECORD_RNA_NEW_XPORT_PROTOCOL: [
            {
                'cache': Cache.IP_PROTOCOLS,
                'id': 'transportProtocol',
                'view': IP_PROTOCOL
            }
        ],

        # 15
        definitions.RECORD_RNA_NEW_CLIENT_APP: [
            {
                'cache': Cache.CLIENT_APPLICATIONS,
                'id': ['client', 'id'],
                'view': CLIENT_APP
            }, {
                'cache': Cache.APPLICATION_PROTOCOLS,
                'id': ['client', 'applicationProto'],
                'view': APP_PROTO
            }
        ],

        # 35
        definitions.RECORD_RNA_CHANGE_CLIENT_APP_TIMEOUT: [
            {
                'cache': Cache.CLIENT_APPLICATIONS,
                'id': ['client', 'id'],
                'view': CLIENT_APP
            }, {
                'cache': Cache.APPLICATION_PROTOCOLS,
                'id': ['client', 'applicationProto'],
                'view': APP_PROTO
            }
        ],

        # 62
        definitions.RECORD_USER: [
            {
                'cache': Cache.USER_PROTOCOLS,
                'id': 'protocol',
                'view': PROTOCOL
            }
        ],

        # 71
        definitions.RECORD_RNA_CONNECTION_STATISTICS: [

        ],

        # 95
        definitions.RUA_EVENT_CHANGE_USER_LOGIN: [
            {
                'cache': Cache.CLIENT_APPLICATIONS,
                'id': ['user', 'applicationId'],
                'view': CLIENT_APP
            }, {
                'cache': Cache.USERS,
                'id': ['user', 'userId'],
                'view': USER
            }
            # These need to be added for version 6.0
            # , {
            #     'cache': Cache.REALMS,
            #     'id': ['user', 'realmId'],
            #     'view': REALM
            # }, {
            #     'cache': Cache.SECURITY_GROUPS,
            #     'id': ['user', 'securityGroupId'],
            #     'view': SECURITY_GROUP
            # }
        ]
    }

    def __init__( self, cache, record ):
        self.cache = cache
        self.record = record
        self.data = {}
        self.logger = estreamer.crossprocesslogging.getLogger( __name__ )



    def __addValueIfAvailable( self, key, cacheKeys ):
        value = self.cache.get( cacheKeys )
        if value:
            self.data[ key ] = value



    def __automap( self, record ):
        recordTypeId = record['recordType']
        if recordTypeId in View.AUTOMAP:
            mappings = View.AUTOMAP[ recordTypeId ]
            for mapping in mappings:
                if isinstance( mapping['id'], list ):
                    value = record
                    for key in mapping['id']:
                        value = value[key]

                    if not isinstance( value, dict ):
                        self.__addValueIfAvailable(
                            mapping['view'],
                            [ mapping['cache'], value ] )

                elif mapping['id'] in record:
                    self.__addValueIfAvailable(
                        mapping['view'],
                        [ mapping['cache'], record[ mapping['id'] ]] )

                else:
                    msg = 'Record (Type={0}) does not have "{1}" attribute'.format(
                        recordTypeId,
                        mapping['id'])

                    self.logger.warning( msg )

    def __isHex(self, s) :
        hex_digits = set("0123456789abcdef")
        for char in s:
            if not (char in hex_digits):
                return False
        return True

    def create( self ):
        """Creates a dictionary with all appropriate record decorations"""
        if 'recordType' not in self.record:
            return {}

        # This method is long. There are possible some things which could be done to
        # make it a bit shorter, but not that much. And it probably wouldn't help all
        # that much anyway. But there are rules:
        #  * the source record stays untouched. DO NOT change it at all. If the calling
        #    method does so, then fine. But not here.
        #  * all data gets written to self.data
        #  * all references to self.data are through CONSTANTS - no strings
        #  * record types are in ascending numerical order and commented with that number

        record = self.record
        recordTypeId = record['recordType']

        self.data[ View.REC_TYPE_SIMPLE ] = definitions.RECORDS[recordTypeId]['category']
        self.data[ View.REC_TYPE_DESCRIPTION ] = definitions.RECORDS[recordTypeId]['name']

        # Take care of automatic lookups here
        self.__automap( record )

        # Now deal with all the other special cases
        if recordTypeId == definitions.RECORD_INTRUSION_IMPACT_ALERT:
            # 9
            impact = record['description']['data']
            # Gets '23' from '[Impact: 23]'
            match = re.search(r'\[Impact:\s(.+?)\]', impact)
            if match != None:
                self.data[ View.DESCRIPTION ] = match.group(1)
            else:
                self.data[ View.DESCRIPTION ] = impact.replace('"', "'")

            self.data[ View.IMPACT ] = Binary.getImpact( record['impact'])


        elif recordTypeId == definitions.METADATA_CORRELATION_POLICY:
            # 69
            self.__addValueIfAvailable(
                View.CORRELATION_RULE,
                [ Cache.CORRELATION_RULES, record['id'], 'name'] )

        elif recordTypeId == definitions.RECORD_RNA_CONNECTION_STATISTICS:
            # 71
            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['protocol']] )

            self.__addValueIfAvailable(
                View.WEB_APP,
                [ Cache.PAYLOADS, record['webApplicationId']] )

            self.__addValueIfAvailable(
                View.CLIENT_APP,
                [
                    Cache.CLIENT_APPLICATIONS,
                    record['clientApplicationId']] )

            self.__addValueIfAvailable(
                View.APP_PROTO,
                [ Cache.APPLICATION_PROTOCOLS, record['applicationId']] )

            self.__addValueIfAvailable(
                View.SEC_INTEL_IP,
                [
                    Cache.SI_SRC_DESTS,
                    record['securityIntelligenceSourceDestination']] )

            if record['securityIntelligenceSourceDestination'] == 0:
                self.data[ View.SEC_INTEL_EVENT ] = 'No'
            else:
                self.data[ View.SEC_INTEL_EVENT ] = 'Yes'

            self.__addValueIfAvailable( View.SEC_INTEL_LIST1, [
                Cache.SI_LISTS_DISCOVERY,
                record['securityIntelligenceList1'],
                record['policyRevision']] )

            self.__addValueIfAvailable( View.SEC_INTEL_LIST2, [
                Cache.SI_LISTS_DISCOVERY,
                record['securityIntelligenceList2'],
                record['policyRevision']] )

            self.__addValueIfAvailable(
                View.URL_CATEGORY,
                [ Cache.URL_CATEGORIES, record['urlCategory']] )

            self.__addValueIfAvailable(
                View.URL_REPUTATION,
                [ Cache.URL_REPUTATIONS, record['urlReputation']] )

            self.__addValueIfAvailable(
                View.FW_RULE,
                [ Cache.FW_RULES, record['policyRevision'], record['ruleId']] )

            self.__addValueIfAvailable(
                View.FW_RULE_ACTION,
                [ Cache.FIREWALL_RULE_ACTIONS, record['ruleAction']] )

            self.__addValueIfAvailable(
                View.FW_RULE_REASON,
                [ Cache.FIREWALL_RULE_REASONS, record['ruleReason']] )

            self.__addValueIfAvailable(
                View.FW_POLICY,
                [ Cache.ACCESS_CONTROL_POLICIES, record['deviceId'], record['policyRevision']] )

            self.__addValueIfAvailable(
                View.IFACE_INGRESS,
                [ Cache.INTERFACES, record['ingressInterface']] )

            self.__addValueIfAvailable(
                View.IFACE_EGRESS,
                [ Cache.INTERFACES, record['egressInterface']] )

            self.__addValueIfAvailable(
                View.SEC_ZONE_INGRESS,
                [ Cache.SECURITY_ZONES, record['ingressZone']] )

            self.__addValueIfAvailable(
                View.SEC_ZONE_EGRESS,
                [ Cache.SECURITY_ZONES, record['egressZone']] )

            self.__addValueIfAvailable(
                View.SOURCE_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['initiatorCountry']] )

            self.__addValueIfAvailable(
                View.DESTINATION_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['responderCountry']] )

            self.__addValueIfAvailable(
                View.USER,
                [ Cache.USERS, record['userId']] )

            self.__addValueIfAvailable(
                View.DNS_RECORD_NAME,
                [ Cache.DNS_RECORDS, record['dnsRecordType'], 'name' ] )

            self.__addValueIfAvailable(
                View.DNS_RECORD_DESCRIPTION,
                [ Cache.DNS_RECORDS, record['dnsRecordType'], 'description' ] )

            self.__addValueIfAvailable(
                View.DNS_RESPONSE_NAME,
                [ Cache.DNS_RESPONSES, record['dnsResponseType'], 'name' ] )

            self.__addValueIfAvailable(
                View.DNS_RESPONSE_DESCRIPTION,
                [
                    Cache.DNS_RESPONSES,
                    record['dnsResponseType'],
                    'description' ] )

            self.__addValueIfAvailable(
                View.SINKHOLE,
                [ Cache.SINKHOLES, record['sinkholeUuid']] )

            self.__addValueIfAvailable(
                View.IOC_CATEGORY,
                [ Cache.IOC, record['iocNumber'], 'category' ] )

            self.__addValueIfAvailable(
                View.SSL_ACTUAL_ACTION,
                [ Cache.SSL_ACTIONS, record['sslActualAction']] )

            self.__addValueIfAvailable(
                View.SSL_EXPECTED_ACTION,
                [ Cache.SSL_ACTIONS, record['sslExpectedAction']] )

            self.__addValueIfAvailable(
                View.SSL_FLOW_FLAGS,
                [ Cache.SSL_FLOW_FLAGS, record['sslFlowFlags']] )

            self.__addValueIfAvailable(
                View.SSL_FLOW_MESSAGES,
                [ Cache.SSL_FLOW_MESSAGES, record['sslFlowMessages']] )

            self.__addValueIfAvailable(
                View.SSL_FLOW_STATUS,
                [ Cache.SSL_FLOWS_STATUSES, record['sslFlowStatus']] )

            self.__addValueIfAvailable(
                View.SSL_SERVER_CERT_STATUS,
                [
                    Cache.SSL_CERT_STATUSES,
                    record['sslServerCertificateStatus']] )

            self.__addValueIfAvailable(
                View.SSL_CIPHER_SUITE,
                [ Cache.SSL_CIPHER_SUITES, record['sslCipherSuite']] )

            self.__addValueIfAvailable(
                View.SSL_VERSION,
                [ Cache.SSL_VERSIONS, record['sslVersion']] )

            self.__addValueIfAvailable(
                View.SSL_URL_CATEGORY,
                [ Cache.SSL_URL_CATEGORIES, record['sslUrlCategory']] )

            for index in range(1, 8):
                inputField = 'monitorRule{0}'.format( index )
                outputField = View.MONITOR_RULE.format( index )
                value = record[ inputField ]

                if value == 0:
                    self.data[ outputField ] = 'N/A'

                self.__addValueIfAvailable(
                    outputField,
                    [
                        Cache.FW_RULES,
                        record['policyRevision'],
                        value] )

        elif recordTypeId == definitions.RUA_EVENT_NEW_USER:
            # 94
            self.__addValueIfAvailable(
                View.USER,
                [ Cache.USERS, record['user']['userId']] )

        elif recordTypeId == definitions.RECORD_RUA_USER:
            # 98
            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['protocol']] )

        elif recordTypeId == definitions.RECORD_RNA_NEW_OS:
            # 101
            self.__addValueIfAvailable(
                View.SOURCE_TYPE,
                [ Cache.SOURCE_TYPES, record['osfingerprint']['sourceType']] )

        elif recordTypeId == definitions.RECORD_RNA_CHANGE_IDENTITY_TIMEOUT:
            # 103
            self.__addValueIfAvailable(
                View.SOURCE_TYPE,
                [ Cache.SOURCE_TYPES, record['identity']['sourceType']] )

            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['identity']['protocol']] )

        elif recordTypeId == definitions.RECORD_RNA_CHANGE_CLIENT_APP_UPDATE:
            # 107
            self.__addValueIfAvailable(
                View.APP_PROTO,
                [ Cache.APPLICATION_PROTOCOLS, record['client']['applicationProto']] )

        elif recordTypeId == definitions.RECORD_INTRUSION_EXTRA_DATA:
            # 110
            self.data[ View.DATA ] = record['blob']['data']
            if(len(str(record['blob']['data']))==32) :
                hex32 = str(record['blob']['data'])

                if(self.__isHex(hex32)) :
                    if(hex32[0:20]=="00000000000000000000") : #ipv4
                        d1 = str(int(hex32[24:26],16))
                        d2 = str(int(hex32[26:28],16))
                        d3 = str(int(hex32[28:30],16))
                        d4 = str(int(hex32[30:32],16))
                        ipv4 = d1 + "." + d2 +"." + d3 + "." + d4
                        self.data[ View.ORIGINAL_CLIENT_SRC_IP ] = ipv4
                    else :
                        h1 = str(hex32[0:4])
                        h2 = str(hex32[4:8])
                        h3 = str(hex32[8:12])
                        h4 = str(hex32[12:16])
                        h5 = str(hex32[16:20])
                        h6 = str(hex32[20:24])
                        h7 = str(hex32[24:28])
                        h8 = str(hex32[28:32])
                        ipv6 = h1 + ":" + h2 + ":" + h3 + ":" + h4 + ":" + h5 + ":" + h6 + ":" + h7 +  ":" + h8

                        self.data[ View.ORIGINAL_CLIENT_SRC_IP ] = ipv6
            self.__addValueIfAvailable(
                View.TYPE,
                [ Cache.XDATA_TYPES, record['type']] )

        elif recordTypeId == definitions.RECORD_CORRELATION_EVENT:
            # 112
            self.__addValueIfAvailable(
                View.EVENT_TYPE,
                [ Cache.CORRELATION_EVENT_TYPES, record['eventType']] )

            self.__addValueIfAvailable(
                View.MSG,
                [ Cache.IDS_RULES, record['signatureGeneratorId'], record['signatureId'] ] )

            self.__addValueIfAvailable(
                View.CORRELATION_RULE,
                [ Cache.CORRELATION_RULES, record['ruleId'], 'name'] )

            self.__addValueIfAvailable(
                View.CORRELATION_POLICY,
                [ Cache.POLICIES, record['policyId']] )

            self.__addValueIfAvailable(
                View.SOURCE_CRITICALITY,
                [ Cache.CORRELATION_CRITICALITY, record['sourceCriticality']] )

            self.__addValueIfAvailable(
                View.DESTINATION_CRITICALITY,
                [ Cache.CORRELATION_CRITICALITY, record['destinationCriticality']] )

            self.__addValueIfAvailable(
                View.SOURCE_HOSTTYPE,
                [ Cache.CORRELATION_HOST_TYPE, record['sourceHostType']] )

            self.__addValueIfAvailable(
                View.DESTINATION_HOSTTYPE,
                [ Cache.CORRELATION_HOST_TYPE, record['destinationHostType']] )

            self.__addValueIfAvailable(
                View.PRIORITY,
                [ Cache.PRIORITIES, record['priority']] )

            self.__addValueIfAvailable(
                View.BLOCKED,
                [ Cache.BLOCKED, record['blocked']] )

            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['ipProtocol']] )

            self.__addValueIfAvailable(
                View.NET_PROTO,
                [ Cache.NET_PROTOS, record['networkProtocol']] )

            self.__addValueIfAvailable(
                View.DESTINATION_APP_PROTO,
                [ Cache.APPLICATION_PROTOCOLS, record['destinationServerId']] )

            self.__addValueIfAvailable(
                View.SOURCE_APP_PROTO,
                [ Cache.APPLICATION_PROTOCOLS, record['sourceServerId']] )

            self.__addValueIfAvailable(
                View.IFACE_INGRESS,
                [ Cache.INTERFACES, record['ingressIntefaceUuid']] )

            self.__addValueIfAvailable(
                View.IFACE_EGRESS,
                [ Cache.INTERFACES, record['egressIntefaceUuid']] )

            self.__addValueIfAvailable(
                View.SEC_ZONE_INGRESS,
                [ Cache.SECURITY_ZONES, record['ingressZoneUuid']] )

            self.__addValueIfAvailable(
                View.SEC_ZONE_EGRESS,
                [ Cache.SECURITY_ZONES, record['egressZoneUuid']] )

            self.__addValueIfAvailable(
                View.SOURCE_OS_NAME,
                [ Cache.OS_FINGERPRINTS, record['sourceOperatingSystemFingerprintUuid'], 'os'] )

            self.__addValueIfAvailable(
                View.SOURCE_OS_VENDOR,
                [
                    Cache.OS_FINGERPRINTS,
                    record['sourceOperatingSystemFingerprintUuid'],
                    'vendor'] )

            self.__addValueIfAvailable(
                View.SOURCE_OS_VERSION,
                [ Cache.OS_FINGERPRINTS, record['sourceOperatingSystemFingerprintUuid'], 'ver'] )

            self.__addValueIfAvailable(
                View.DESTINATION_OS_NAME,
                [
                    Cache.OS_FINGERPRINTS,
                    record['destinationOperatingSystemFingerprintUuid'],
                    'os'] )

            self.__addValueIfAvailable(
                View.DESTINATION_OS_VENDOR,
                [
                    Cache.OS_FINGERPRINTS,
                    record['destinationOperatingSystemFingerprintUuid'],
                    'vendor'] )

            self.__addValueIfAvailable(
                View.DESTINATION_OS_VERSION,
                [
                    Cache.OS_FINGERPRINTS,
                    record['destinationOperatingSystemFingerprintUuid'],
                    'ver'] )

            self.__addValueIfAvailable(
                View.SOURCE_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['sourceCountry']] )

            self.__addValueIfAvailable(
                View.DESTINATION_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['destinationCountry']] )

            self.__addValueIfAvailable(
                View.SOURCE_USER,
                [ Cache.USERS, record['sourceUserId']] )

            self.__addValueIfAvailable(
                View.DESTINATION_USER,
                [ Cache.USERS, record['destinationUserId']] )

            self.__addValueIfAvailable(
                View.SEC_INTEL_POLICY,
                [ Cache.SI_LISTS_GENERAL, record['securityIntelligenceUuid']] )

            self.__addValueIfAvailable(
                View.SSL_ACTUAL_ACTION,
                [ Cache.SSL_ACTIONS, record['sslActualAction']] )

            self.__addValueIfAvailable(
                View.SSL_FLOW_STATUS,
                [ Cache.SSL_FLOWS_STATUSES, record['sslFlowStatus']] )

            self.__addValueIfAvailable(
                View.URL_REPUTATION,
                [ Cache.URL_REPUTATIONS, record['urlReputation']] )

            self.__addValueIfAvailable(
                View.URL_CATEGORY,
                [ Cache.URL_CATEGORIES, record['urlCategory']] )

            if 'eventImpactFlags' in record:
                self.data[ View.IMPACT ] = Binary.getImpact( record['eventImpactFlags'] )

            # Don't know why, but this exists
            self.data[ View.DESCRIPTION ] = ''

            # Let's "fix" the IP fields for consistency
            if 'sourceIpv6Address' in record \
                    and record['sourceIp'] == '0.0.0.0' \
                    and record['sourceIpv6Address'] != '::':
                self.data[ View.SOURCE_IP ] = record['sourceIpv6Address']

            if 'destinationIpv6Address' in record \
                    and record['destinationIp'] == '0.0.0.0' \
                    and record['destinationIpv6Address'] != '::':
                self.data[ View.DESTINATION_IP ] = record['destinationIpv6Address']

        elif recordTypeId == definitions.METADATA_ACCESS_CONTROL_RULE_ID:
            # 119
            # This may need to use the uuid instead in which case
            # add an additional mapping (see policy_uuid below)
            # This used to be "revision"
            if 'ruleId' in record:
                self.__addValueIfAvailable(
                    View.FW_POLICY,
                    ['policies', record['ruleId']] )

        elif recordTypeId == definitions.RECORD_MALWARE_EVENT:
            # 125
            self.__addValueIfAvailable(
                View.CLOUD,
                [ Cache.CLOUDS, record['cloudUuid']] )

            self.__addValueIfAvailable(
                View.MALWARE_EVENT_TYPE,
                [ Cache.MALWARE_EVENT_TYPES, record['eventTypeId']] )

            self.__addValueIfAvailable(
                View.MALWARE_EVENT_SUBTYPE,
                [ Cache.FIREAMP_SUBTYPES, record['eventSubtypeId']] )

            self.__addValueIfAvailable(
                View.FILE_ACTION,
                [ Cache.FILE_ACTIONS, record['action']] )

            if record['detectionName']['data'] == '':
                self.__addValueIfAvailable(
                    View.DETECTION_NAME,
                    [ Cache.FILE_SHAS, record['fileShaHash']['data']] )

            self.__addValueIfAvailable(
                View.PARENT_DETECTION,
                [ Cache.FILE_SHAS, record['parentShaHash']['data']] )

            self.__addValueIfAvailable(
                View.TYPE,
                [ Cache.FIREAMP_TYPES, record['eventTypeId']] )

            self.__addValueIfAvailable(
                View.SUBTYPE,
                [ Cache.FIREAMP_SUBTYPES, record['eventSubtypeId']] )

            self.__addValueIfAvailable(
                View.DETECTOR,
                [ Cache.FIREAMP_DETECTORS, record['detectorId']] )

            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['protocol']] )

            self.__addValueIfAvailable(
                View.DISPOSITION,
                [ Cache.FILE_DISPOSITIONS, record['disposition']] )

            self.__addValueIfAvailable(
                View.RETRO_DISPOSITION,
                [ Cache.FILE_DISPOSITIONS, record['retroDisposition']] )

            self.__addValueIfAvailable(
                View.FILE_TYPE,
                [ Cache.FILE_TYPES, record['fileType']] )

            self.__addValueIfAvailable(
                View.WEB_APP,
                [ Cache.PAYLOADS, record['webApplicationId']] )

            self.__addValueIfAvailable(
                View.CLIENT_APP,
                [ Cache.CLIENT_APPLICATIONS, record['clientApplicationId']] )

            self.__addValueIfAvailable(
                View.APP_PROTO,
                [ Cache.APPLICATION_PROTOCOLS, record['applicationId']] )

            self.__addValueIfAvailable(
                View.FILE_POLICY,
                [ Cache.POLICIES, record['accessControlPolicyUuid']] )

            self.__addValueIfAvailable(
                View.DIRECTION,
                [ Cache.DIRECTIONS, record['direction']] )

            self.__addValueIfAvailable(
                View.SOURCE_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['sourceCountry']] )

            self.__addValueIfAvailable(
                View.DESTINATION_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['destinationCountry']] )

            self.__addValueIfAvailable(
                View.AGENT_USER,
                [ Cache.USERS, record['userId']] )

            self.__addValueIfAvailable(
                View.USER,
                [ Cache.USERS, record['user']['data']] )

            self.__addValueIfAvailable(
                View.IOC_CATEGORY,
                [ Cache.IOC, record['iocNumber'], 'category'] )

            self.__addValueIfAvailable(
                View.SSL_ACTUAL_ACTION,
                [ Cache.SSL_ACTIONS, record['sslActualAction'] ] )

            self.__addValueIfAvailable(
                View.SSL_FLOW_STATUS,
                [ Cache.SSL_FLOWS_STATUSES, record['sslFlowStatus'] ] )

        elif recordTypeId == definitions.METADATA_ICMP_TYPE:
            # 260
            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['protocol']] )

        elif recordTypeId == definitions.METADATA_ICMP_CODE:
            # 270
            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['protocol']] )

        elif recordTypeId == definitions.METADATA_SECURITY_INTELLIGENCE_CATEGORY_DISCOVERY:
            # 280
            self.__addValueIfAvailable(
                View.FW_POLICY,
                [ Cache.POLICIES, record['accessControlPolicyUuid']] )

        elif recordTypeId == definitions.RECORD_INTRUSION_EVENT:
            # 400
            self.__addValueIfAvailable(
                View.MSG,
                [ Cache.IDS_RULES, record['generatorId'], record['ruleId']] )

            self.__addValueIfAvailable(
                View.RENDERED_ID,
                [ Cache.IDS_RULES_RENDERED, record['generatorId'], record['ruleId']] )

            self.__addValueIfAvailable(
                View.CLASSIFICATION_DESCRIPTION,
                [ Cache.CLASSIFICATIONS, record['classificationId'], 'desc'] )

            self.__addValueIfAvailable(
                View.CLASSIFICATION_NAME,
                [ Cache.CLASSIFICATIONS, record['classificationId'], 'name'] )

            self.__addValueIfAvailable(
                View.IDS_POLICY,
                [ Cache.POLICIES, record['policyUuid']] )

            self.__addValueIfAvailable(
                View.FW_RULE,
                [ Cache.FW_RULES,
                record['accessControlPolicyUuid'],
                record['accessControlRuleId']] )

            self.__addValueIfAvailable( View.FW_POLICY, [
                Cache.ACCESS_CONTROL_POLICIES,
                record['deviceId'],
                record['accessControlPolicyUuid']] )

            self.__addValueIfAvailable(
                View.PRIORITY,
                [ Cache.PRIORITIES, record['priorityId']] )

            self.__addValueIfAvailable(
                View.BLOCKED,
                [ Cache.BLOCKED, record['blocked']] )

            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['ipProtocolId']] )

            self.__addValueIfAvailable(
                View.WEB_APP,
                [ Cache.PAYLOADS, record['webApplicationId']] )

            self.__addValueIfAvailable(
                View.CLIENT_APP,
                [ Cache.CLIENT_APPLICATIONS, record['clientApplicationId']] )

            self.__addValueIfAvailable(
                View.APP_PROTO,
                [ Cache.APPLICATION_PROTOCOLS, record['applicationId']] )

            self.__addValueIfAvailable(
                View.IFACE_INGRESS,
                [ Cache.INTERFACES, record['interfaceIngressUuid']] )

            self.__addValueIfAvailable(
                View.IFACE_EGRESS,
                [ Cache.INTERFACES, record['interfaceEgressUuid']] )

            self.__addValueIfAvailable(
                View.SEC_ZONE_INGRESS,
                [ Cache.SECURITY_ZONES, record['securityZoneIngressUuid']] )

            self.__addValueIfAvailable(
                View.SEC_ZONE_EGRESS,
                [ Cache.SECURITY_ZONES, record['securityZoneEgressUuid']] )

            self.__addValueIfAvailable(
                View.SOURCE_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['sourceCountry']] )

            self.__addValueIfAvailable(
                View.DESTINATION_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['destinationCountry']] )

            self.__addValueIfAvailable(
                View.USER,
                [ Cache.USERS, record['userId']] )

            self.__addValueIfAvailable(
                View.IOC_CATEGORY,
                [ Cache.IOC, record['iocNumber'], 'category'] )

            self.__addValueIfAvailable(
                View.SSL_ACTUAL_ACTION,
                [ Cache.SSL_ACTIONS, record['sslActualAction'] ] )

            self.__addValueIfAvailable(
                View.SSL_FLOW_STATUS,
                [ Cache.SSL_FLOWS_STATUSES, record['sslFlowStatus'] ] )

            self.data[ View.IMPACT ] = Binary.getImpact( record['impactFlags'] )

            self.__addValueIfAvailable(
                View.IMPACT_DESCRIPTION,
                [ Cache.IMPACT, record['impact'] ] )

            self.__addValueIfAvailable(
                View.NETWORK_ANALYSIS_POLICY,
                [ Cache.POLICIES, record['networkAnalysisPolicyUuid'] ] )

        elif recordTypeId == definitions.RECORD_FILELOG_EVENT or \
             recordTypeId == definitions.RECORD_FILELOG_MALWARE_EVENT:
            # 500 or 502
            self.__addValueIfAvailable(
                View.FILE_POLICY,
                [ Cache.POLICIES, record['accessControlPolicyUuid']] )

            self.__addValueIfAvailable(
                View.FILE_ACTION,
                [ Cache.FILE_ACTIONS, record['action']] )

            self.__addValueIfAvailable(
                View.DETECTION,
                [ Cache.FILE_SHAS, record[ 'shaHash' ]] )

            self.__addValueIfAvailable(
                View.IP_PROTOCOL,
                [ Cache.IP_PROTOCOLS, record['protocol']] )

            self.__addValueIfAvailable(
                View.DISPOSITION,
                [ Cache.FILE_DISPOSITIONS, record['disposition']] )

            self.__addValueIfAvailable(
                View.SPERO_DISPOSITION,
                [ Cache.FILE_DISPOSITIONS, record['speroDisposition']] )

            self.__addValueIfAvailable(
                View.FILE_STORAGE_STATUS,
                [ Cache.FILE_STORAGES, record['fileStorageStatus']] )

            self.__addValueIfAvailable(
                View.FILE_ANALYSIS_STATUS,
                [ Cache.FILE_STATIC_ANALYSES, record['fileAnalysisStatus']] )

            self.__addValueIfAvailable(
                View.FILE_TYPE,
                [ Cache.FILE_TYPES, record['fileTypeId']] )

            self.__addValueIfAvailable(
                View.WEB_APP,
                [ Cache.PAYLOADS, record['webApplicationId']] )

            self.__addValueIfAvailable(
                View.CLIENT_APP,
                [ Cache.CLIENT_APPLICATIONS, record['clientApplicationId']] )

            self.__addValueIfAvailable(
                View.APP_PROTO,
                [ Cache.APPLICATION_PROTOCOLS, record['applicationId']] )

            self.__addValueIfAvailable(
                View.DIRECTION,
                [ Cache.DIRECTIONS, record['direction']] )

            self.__addValueIfAvailable(
                View.SOURCE_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['sourceCountry']] )

            self.__addValueIfAvailable(
                View.DESTINATION_IP_COUNTRY,
                [ Cache.GEOLOCATIONS, record['destinationCountry']] )

            self.__addValueIfAvailable(
                View.USER,
                [ Cache.USERS, record['userId']] )

            self.__addValueIfAvailable(
                View.SSL_ACTUAL_ACTION,
                [ Cache.SSL_ACTIONS, record['sslActualAction'] ] )

            self.__addValueIfAvailable(
                View.SSL_FLOW_STATUS,
                [ Cache.SSL_FLOWS_STATUSES, record['sslFlowStatus'] ] )

            self.__addValueIfAvailable(
                View.MALWARE_ANALYSIS_STATUS,
                [ Cache.MALWARE_ANALYSIS_STATUS, record['localMalwareAnalysisStatus'] ] )

            self.__addValueIfAvailable(
                View.ARCHIVE_FILE_STATUS,
                [ Cache.FILE_ARCHIVE_STATUS, record['archiveFileStatus'] ] )

        elif recordTypeId == definitions.METADATA_FILELOG_SHA:
            # 511
            self.__addValueIfAvailable(
                View.DISPOSITION,
                [ Cache.FILE_DISPOSITIONS, record['disposition']] )

        # Now do the general cases
        if 'sensorId' in record:
            self.data[ View.SENSOR ] = self.cache.get([ Cache.DEVICES, record['sensorId']])

        if 'deviceId' in record:
            self.data[ View.SENSOR ] = self.cache.get([ Cache.DEVICES, record['deviceId']])

        if 'eventType' in record:
            eventType = record['eventType']

            if 'eventSubtype' in record:
                eventSubtype = record['eventSubtype']
                if eventType in definitions.RNA_TYPE_NAMES and \
                   eventSubtype in definitions.RNA_TYPE_NAMES[ eventType ]:
                    self.data[ View.EVENT_DESC ] = \
                        definitions.RNA_TYPE_NAMES[ eventType ][ eventSubtype ]

        if 'sourceId' in record:
            # None of these are mapped from RNA records
            self.__addValueIfAvailable(
                View.SOURCE,
                [ Cache.SOURCE_APPLICATIONS, record['sourceId'] ] )

        eventSec = 0
        eventUsec = 0

        # See if we can find the timestamps
        if 'eventSecond' in record:
            eventSec = record['eventSecond']
            if 'eventMicrosecond' in record:
                eventUsec = record['eventMicrosecond']

        elif 'fileEventTimestamp' in record:
            eventSec = record['fileEventTimestamp']

        elif 'triggerEventSecond' in record:
            eventSec = record['triggerEventSecond']
            if 'triggerEventMicrosecond' in record:
                eventUsec = record['triggerEventMicrosecond']

        elif 'timestamp' in record:
            eventSec = record['timestamp']

        # If not timestamp exists, let's try the archive timestamp
        if eventSec == 0:
            eventSec = record['archiveTimestamp']

        # Push the timestamp fields in where applicable
        if eventSec > 0:
            self.data[ View.EVENT_SEC ] = eventSec
            timestamp = eventSec + ( eventUsec / 1000000.0 )
            eventDateTime = datetime.datetime.fromtimestamp( timestamp )
            self.data[ View.EVENT_TIMESTAMP ] = eventDateTime.isoformat()

        if eventUsec > 0:
            self.data[ View.EVENT_USEC ] = eventUsec

        return self.data
