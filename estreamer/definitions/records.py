
#********************************************************************
#      File:    records.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       This file contains all record types which estreamer can send
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

#pylint: disable=W0401,W0614
from estreamer.definitions.blocks_series1 import *
from estreamer.definitions.blocks_series2 import *
from estreamer.definitions.core import *

RECORDS = {
    # 2
    RECORD_PACKET: {
        'name': u'Packet Data',
        'attributes': [
            { 'type': TYPE_UINT32, 'name': 'deviceId' },
            { 'type': TYPE_UINT32, 'name': 'eventId' },
            { 'type': TYPE_UINT32, 'name': 'eventSecond' },
            { 'type': TYPE_UINT32, 'name': 'packetSecond' },
            { 'type': TYPE_UINT32, 'name': 'packetMicrosecond' },
            { 'type': TYPE_UINT32, 'name': 'linkType' },
            { 'type': TYPE_UINT32, 'name': 'packetLength' },
            { 'type': TYPE_VARIABLE, 'length': 'packetLength', 'name': 'packetData'}],
        'category': u'PACKET' },

    # 4
    RECORD_PRIORITY: {
        'name': u'Priority Metadata',
        'attributes': [
            { 'type': TYPE_UINT32, 'name': 'id' },
            { 'type': TYPE_UINT16, 'name': 'length' },
            { 'type': TYPE_VARIABLE, 'length': 'length', 'name': 'name' }
        ],
        'category': u'PRIORITY' },

    # 9
    RECORD_INTRUSION_IMPACT_ALERT: {
        'name': u'Intrusion Impact Alert',
        'attributes': [ { 'block': BLOCK_INTRUSION_IMPACT_ALERT_53 }],
        'category': u'IMPACT' },

    # 10
    RECORD_RNA_NEW_HOST: {
        'name': u'New Host Detected',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_PROFILE_DATA_52, 'name': 'hostProfile' }],
        'category': u'RNA' },

    # 11
    RECORD_RNA_NEW_TCP_SERVICE: {
        'name': u'New TCP Server',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_SERVER_DATA_41, 'name': 'hostServer'}],
        'category': u'RNA' },

    # 12
    RECORD_RNA_NEW_UDP_SERVICE: {
        'name': u'New UDP Server',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_SERVER_DATA_41, 'name': 'hostServer'}],
        'category': u'RNA' },

    # 13
    RECORD_RNA_NEW_NET_PROTOCOL: {
        'name': u'New Network Protocol',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_UINT16, 'name': 'networkProtocol'}],
        'category': u'RNA' },

    # 14
    RECORD_RNA_NEW_XPORT_PROTOCOL: {
        'name': u'New Transport Protocol',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_BYTE, 'name': 'transportProtocol'}],
        'category': u'RNA' },

    # 15
    RECORD_RNA_NEW_CLIENT_APP: {
        'name': u'New Client Application',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_CLIENT_APPLICATION_50, 'name': 'client' }],
        'category': u'RNA' },

    # 16
    RECORD_RNA_CHANGE_TCP_SERVICE_INFO: {
        'name': u'TCP Server Information Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_SERVER_DATA_41, 'name': 'hostServer'}],
        'category': u'RNA' },

    # 17
    RECORD_RNA_CHANGE_UDP_SERVICE_INFO: {
        'name': u'UDP Server Information Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_SERVER_DATA_41, 'name': 'hostServer'}],
        'category': u'RNA' },

    # 18
    RECORD_RNA_CHANGE_OS: {
        'name': u'OS Information Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_OPERATING_SYSTEM_DATA_35 }],
        'category': u'RNA' },

    # 19
    RECORD_RNA_CHANGE_HOST_TIMEOUT: {
        'name': u'Host Timeout',
        'attributes': [ { 'discovery': True }],
        'category': u'RNA' },

    # 20
    RECORD_RNA_CHANGE_HOST_REMOVE: {
        'name': u'Host IP Address Reused',
        'attributes': [ { 'discovery': True }],
        'category': u'RNA' },

    # 21
    RECORD_RNA_CHANGE_HOST_ANR_DELETE: {
        'name': u'Host Deleted: Host Limit Reached',
        'attributes': [ { 'discovery': True }],
        'category': u'RNA' },

    # 22
    RECORD_RNA_CHANGE_HOPS: {
        'name': u'Hops Change',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_BYTE, 'name': 'hops'}],
        'category': u'RNA' },

    # 23
    RECORD_RNA_CHANGE_TCP_PORT_CLOSED: {
        'name': u'TCP Port Closed',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_UINT16, 'name': 'port'}],
        'category': u'RNA' },

    # 24
    RECORD_RNA_CHANGE_UDP_PORT_CLOSED: {
        'name': u'UDP Port Closed',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_UINT16, 'name': 'port'}],
        'category': u'RNA' },

    # 25
    RECORD_RNA_CHANGE_TCP_PORT_TIMEOUT: {
        'name': u'TCP Port Timeout',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_UINT16, 'name': 'port'}],
        'category': u'RNA' },

    # 26
    RECORD_RNA_CHANGE_UDP_PORT_TIMEOUT: {
        'name': u'UDP Port Timeout',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_UINT16, 'name': 'port' }],
        'category': u'RNA' },

    # 27
    RECORD_RNA_CHANGE_MAC_INFO: {
        'name': u'MAC Information Change',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_MAC_ADDRESS_49, 'name': 'mac' }],
        'category': u'RNA' },

    # 28
    RECORD_RNA_CHANGE_MAC_ADD: {
        'name': u'Additional MAC Detected for Host',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_MAC_ADDRESS_49, 'name': 'mac' }],
        'category': u'RNA' },

    # 29
    RECORD_RNA_CHANGE_HOST_IP: {
        'name': u'Host IP Address Changed',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_IPV6, 'name': 'ipAddress' }],
        'category': u'RNA' },

    # 31
    RECORD_RNA_CHANGE_HOST_TYPE: {
        'name': u'Host Identified as Router/Bridge',
        'attributes': [
            { 'discovery': True },
            { 'type': TYPE_UINT32, 'name': 'hostType'}],
        'category': u'RNA' },

    # 34
    RECORD_RNA_CHANGE_VLAN_TAG: {
        'name': u'VLAN Tag Information Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_VLAN_DATA }],
        'category': u'RNA' },

    # 35
    RECORD_RNA_CHANGE_CLIENT_APP_TIMEOUT: {
        'name': u'Client Application Timeout',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_CLIENT_APPLICATION_50, 'name': 'client' }],
        'category': u'RNA' },

    # 42
    RECORD_RNA_CHANGE_NETBIOS_NAME: {
        'name': u'NetBIOS Name Change',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_STRING_INFORMATION }],
        'category': u'RNA' },

    # 44
    RECORD_RNA_CHANGE_HOST_DROPPED: {
        'name': u'Host Dropped: Host Limit Reached',
        'attributes': [ { 'discovery': True }],
        'category': u'RNA' },

    # 45
    RECORD_RNA_CHANGE_BANNER_UPDATE: {
        'name': u'Update Banner',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_SERVER_BANNER }],
        'category': u'RNA' },

    # 46
    RECORD_RNA_USER_ADD_ATTRIBUTE: {
        'name': u'Add Host Attribute',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_ATTRIBUTE_DEFINITION_47 }],
        'category': u'RNA' },

    # 47
    RECORD_RNA_USER_UPDATE_ATTRIBUTE: {
        'name': u'Update Host Attribute',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_ATTRIBUTE_DEFINITION_47 }],
        'category': u'RNA' },

    # 48
    RECORD_RNA_USER_DELETE_ATTRIBUTE: {
        'name': u'Delete Host Attribute',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_ATTRIBUTE_DEFINITION_47 }],
        'category': u'RNA' },

    # 51
    RECORD_RNA_CHANGE_TCP_SERVICE_CONFIDENCE: {
        'name': u'TCP Server Confidence Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_SERVER_DATA_41 }],
        'category': u'RNA' },

    # 52
    RECORD_RNA_CHANGE_UDP_SERVICE_CONFIDENCE: {
        'name': u'UDP Server Confidence Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_SERVER_DATA_41 }],
        'category': u'RNA' },

    # 53
    RECORD_RNA_CHANGE_OS_CONFIDENCE: {
        'name': u'OS Confidence Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_OPERATING_SYSTEM_DATA_35 }],
        'category': u'RNA' },

    # 54
    METADATA_RNA_FINGERPRINT: {
        'name': u'Fingerprint Metadata',
        'attributes': [
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'type': TYPE_UINT32, 'name': 'nameLength' },
            { 'type': TYPE_VARIABLE, 'length': 'nameLength', 'name': 'name' },
            { 'type': TYPE_UINT32, 'name': 'vendorLength' },
            { 'type': TYPE_VARIABLE, 'length': 'vendorLength', 'name': 'vendor' },
            { 'type': TYPE_UINT32, 'name': 'versionLength' },
            { 'type': TYPE_VARIABLE, 'length': 'versionLength', 'name': 'version'}],
        'category': u'FINGERPRINT' },

    # 55
    METADATA_RNA_CLIENT_APPLICATION: {
        'name': u'Client Application Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'CLIENT APP' },

    # 57
    METADATA_RNA_VULNERABILITY: {
        'name': u'Vulnerability Metadata',
        'attributes': [
            { 'type': TYPE_UINT32, 'name': 'id' },
            { 'type': TYPE_UINT32, 'name': 'impact' },
            { 'type': TYPE_BYTE, 'name': 'exploits' },
            { 'type': TYPE_BYTE, 'name': 'remote' },
            { 'type': TYPE_UINT32, 'name': 'entryDateLength' },
            { 'type': TYPE_VARIABLE, 'length': 'entryDateLength', 'name': 'entryDate' },
            { 'type': TYPE_UINT32, 'name': 'publishedDateLength' },
            { 'type': TYPE_VARIABLE, 'length': 'publishedDateLength', 'name': 'publishedDate' },
            { 'type': TYPE_UINT32, 'name': 'modifiedDateLength' },
            { 'type': TYPE_VARIABLE, 'length': 'modifiedDateLength', 'name': 'modifiedDate' },
            { 'type': TYPE_UINT32, 'name': 'titleLength' },
            { 'type': TYPE_VARIABLE, 'length': 'titleLength', 'name': 'title' },
            { 'type': TYPE_UINT32, 'name': 'shortDescriptionLength' },
            {
                'type': TYPE_VARIABLE,
                'length': 'shortDescriptionLength',
                'name': 'shortDescription' },
            { 'type': TYPE_UINT32, 'name': 'descriptionLength' },
            { 'type': TYPE_VARIABLE, 'length': 'descriptionLength', 'name': 'description' },
            { 'type': TYPE_UINT32, 'name': 'technicalDescriptionLength' },
            {
                'type': TYPE_VARIABLE,
                'length': 'technicalDescriptionLength',
                'name': 'technicalDescription' },
            { 'type': TYPE_UINT32, 'name': 'solutionLength' },
            { 'type': TYPE_VARIABLE, 'length': 'solutionLength', 'name': 'solution' } ],
        'category': u'VULNERABILITY' },

    # 58
    METADATA_RNA_CRITICALITY: {
        'name': u'Criticality Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'CRITICALITY' },

    # 59
    METADATA_RNA_NETWORK_PROTOCOL: {
        'name': u'Network Protocol Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'NETWORK' },

    # 60
    METADATA_RNA_ATTRIBUTE: {
        'name': u'Attribute Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'ATTRIBUTE' },

    # 61
    METADATA_RNA_SCAN_TYPE: {
        'name': u'Scan Type Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SCAN TYPE' },

    # 62
    RECORD_USER: {
        'name': u'User Metadata',
        'attributes': [ { 'block': BLOCK_USER_60 } ],
        'category': u'SYSTEM USER' },

    # 63
    METADATA_RNA_SERVICE: {
        'name': u'Server Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SERVICE' },

    # 66
    METADATA_RULE_MESSAGE: {
        'name': u'Rule Message Metadata',
        'attributes': [
            { 'type': TYPE_UINT32, 'name': 'generatorId' },
            { 'type': TYPE_UINT32, 'name': 'ruleId' },
            { 'type': TYPE_UINT32, 'name': 'ruleRevision' },
            { 'type': TYPE_UINT32, 'name': 'signatureId' },
            { 'type': TYPE_UINT16, 'name': 'messageLength' },
            { 'type': TYPE_UUID, 'name': 'ruleUuid' },
            { 'type': TYPE_UUID, 'name': 'ruleRevisionUuid' },
            { 'type': TYPE_VARIABLE, 'length': 'messageLength', 'name': 'message'}],
        'category': u'RULE' },

    # 67
    METADATA_CLASSIFICATION: {
        'name': u'Classification Metadata',
        'attributes': [
            { 'type': TYPE_UINT32, 'name': 'id' },
            { 'type': TYPE_UINT16, 'name': 'nameLength' },
            { 'type': TYPE_VARIABLE, 'length': 'nameLength', 'name': 'name'},
            { 'type': TYPE_UINT16, 'name': 'descriptionLength' },
            { 'type': TYPE_VARIABLE, 'length': 'descriptionLength', 'name': 'description'},
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'type': TYPE_UUID, 'name': 'revisionUuid' }],
        'category': u'CLASSIFICATION' },

    # 69
    METADATA_CORRELATION_POLICY: {
        'name': u'Correlation Policy Metadata',
        'attributes': [
            # Documentation diagram is incorrect. See sizes in notes
            { 'type': TYPE_UINT32, 'name': 'id' },
            { 'type': TYPE_UINT16, 'name': 'nameLength' },
            { 'type': TYPE_VARIABLE, 'length': 'nameLength', 'name': 'name' },
            { 'type': TYPE_UINT16, 'name': 'descriptionLength' },
            { 'type': TYPE_VARIABLE, 'length': 'descriptionLength', 'name': 'description' },
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'type': TYPE_UUID, 'name': 'revisionUuid' }],
        'category': u'POLICY' },

    # 70
    METADATA_CORRELATION_RULE: {
        'name': u'Correlation Rule Metadata',
        'attributes': [
            { 'type': TYPE_UINT32, 'name': 'id' },
            { 'type': TYPE_UINT16, 'name': 'nameLength' },
            { 'type': TYPE_VARIABLE, 'length': 'nameLength', 'name': 'name' },
            { 'type': TYPE_UINT16, 'name': 'descriptionLength' },
            { 'type': TYPE_VARIABLE, 'length': 'descriptionLength', 'name': 'description' },
            { 'type': TYPE_UINT16, 'name': 'eventTypeLength' },
            { 'type': TYPE_VARIABLE, 'length': 'eventTypeLength', 'name': 'eventType' },
            { 'type': TYPE_UUID, 'name': 'correlationRuleUuid' },
            { 'type': TYPE_UUID, 'name': 'correlationRevisionUuid' },
            { 'type': TYPE_UUID, 'name': 'whitelistUuid' }],
        'category': u'RULE' },

    # 71
    RECORD_RNA_CONNECTION_STATISTICS: {
        'name': u'Connection Statistics',
        'attributes': [
            { 'discovery': True },
            # This will be 160 or 163
            { 'block': BLOCK_AUTO }],
        'category': u'RNA' },

    # 73
    RECORD_RNA_CONNECTION_CHUNK: {
        'name': u'Connection Chunk',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_CONNECTION_CHUNK_511 }],
        'category': u'RNA' },

    # 74
    RECORD_RNA_USER_SET_OS: {
        'name': u'User Set OS',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_PRODUCT_DATA_51 }],
        'category': u'RNA' },

    # 75
    RECORD_RNA_USER_SET_SERVICE: {
        'name': u'User Set Server',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_PRODUCT_DATA_51 }],
        'category': u'RNA' },

    # 76
    RECORD_RNA_USER_DELETE_PROTOCOL: {
        'name': u'User Delete Protocol',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_PROTOCOL_LIST_47 }],
        'category': u'RNA' },

    # 77
    RECORD_RNA_USER_DELETE_CLIENT_APP: {
        'name': u'User Delete Client Application',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_CLIENT_APPLICATION_LIST }],
        'category': u'RNA' },

    # 78
    RECORD_RNA_USER_DELETE_ADDRESS: {
        'name': u'User Delete Address',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_HOSTS_47 }],
        'category': u'RNA' },

    # 79
    RECORD_RNA_USER_DELETE_SERVICE: {
        'name': u'User Delete Server',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_SERVER_LIST }],
        'category': u'RNA' },

    # 80
    RECORD_RNA_USER_VULNERABILITIES_VALID: {
        'name': u'User Set Valid Vulnerabilities',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_VULNERABILITY_CHANGE_47 }],
        'category': u'RNA' },

    # 81
    RECORD_RNA_USER_VULNERABILITIES_INVALID: {
        'name': u'User Set Invalid Vulnerabilities',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_VULNERABILITY_CHANGE_47 }],
        'category': u'RNA' },

    # 82
    RECORD_RNA_USER_SET_CRITICALITY: {
        'name': u'User Set Host Criticality',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_CRITICALITY_CHANGE_47 }],
        'category': u'RNA' },

    # 83
    RECORD_RNA_USER_SET_ATTRIBUTE_VALUE: {
        'name': u'User Set Attribute Value',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_ATTRIBUTE_VALUE_47 }],
        'category': u'RNA' },

    # 84
    RECORD_RNA_USER_DELETE_ATTRIBUTE_VALUE: {
        'name': u'User Delete Attribute Value',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_ATTRIBUTE_VALUE_47 }],
        'category': u'RNA' },

    # 85
    RECORD_RNA_USER_ADD_HOST: {
        'name': u'User Add Host',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_HOSTS_47 }],
        'category': u'RNA' },

    # 86
    RECORD_RNA_USER_ADD_SERVICE: {
        'name': u'User Add Server',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_PRODUCT_DATA_51 }],
        'category': u'RNA' },

    # 87
    RECORD_RNA_USER_ADD_CLIENT_APP: {
        'name': u'User Add Client Application',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_CLIENT_APPLICATION_LIST }],
        'category': u'RNA' },

    # 88
    RECORD_RNA_USER_ADD_PROTOCOL: {
        'name': u'User Add Protocol',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_PROTOCOL_LIST_47 }],
        'category': u'RNA' },

    # 89
    RECORD_RNA_USER_ADD_SCAN_RESULT: {
        'name': u'User Add Scan Result',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_SCAN_RESULT_DATA_52 }],
        'category': u'RNA' },

    # 90
    METADATA_RNA_SOURCE_TYPE: {
        'name': u'Source Type',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SOURCE TYPE' },

    # 91
    METADATA_RNA_SOURCE_APP: {
        'name': u'Source Application',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SOURCE APP' },

    # 92
    RUA_EVENT_CHANGE_USER_DROPPED: {
        'name': u'User Dropped Change Event',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_INFORMATION_DATA_50, 'name': 'user'}],
        'category': u'RUA' },

    # 93
    RUA_EVENT_CHANGE_USER_REMOVE: {
        'name': u'User Removed Change Event',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_INFORMATION_DATA_50, 'name': 'user'}],
        'category': u'RUA' },

    # 94
    RUA_EVENT_NEW_USER: {
        'name': u'New User Identification Event',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_INFORMATION_DATA_50, 'name': 'user'}],
        'category': u'RUA' },

    # 95
    RUA_EVENT_CHANGE_USER_LOGIN: {
        'name': u'User Login Change Event',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_USER_LOGIN_INFORMATION_54, 'name': 'user' },
        ],
        'category': u'RUA' },

    # 96
    METADATA_RNA_SOURCE_DETECTOR: {
        'name': u'Source Detector',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SOURCE DETECTOR' },

    # 98
    RECORD_RUA_USER: {
        'name': u'User',
        'attributes': [ { 'block': BLOCK_USER_60 } ],
        'category': u'RUA USER' },

    # 101
    RECORD_RNA_NEW_OS: {
        'name': u'New OS Event',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'osfingerprint' }],
        'category': u'RNA' },

    # 102
    RECORD_RNA_CHANGE_IDENTITY_CONFLICT: {
        'name': u'Identity Conflict Event',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_IDENTITY_DATA, 'name': 'identity' }],
        'category': u'RNA' },

    # 103
    RECORD_RNA_CHANGE_IDENTITY_TIMEOUT: {
        'name': u'Identity Timeout Event',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_IDENTITY_DATA, 'name': 'identity' }],
        'category': u'RNA' },

    # 106
    RECORD_THIRD_PARTY_SCAN_VULNERABILITY: {
        'name': u'Third Party Scanner Vulnerability',
        'attributes': [
            { 'type': TYPE_UINT32, 'name': 'id' },
            { 'type': TYPE_UINT32, 'name': 'scannerType' },
            { 'type': TYPE_UINT32, 'name': 'titleLength' },
            { 'type': TYPE_VARIABLE, 'length': 'titleLength', 'name': 'title' },
            { 'type': TYPE_UINT32, 'name': 'descriptionLength' },
            { 'type': TYPE_VARIABLE, 'length': 'descriptionLength', 'description': 'title' },
            { 'type': TYPE_UINT32, 'name': 'cveIdLength' },
            { 'type': TYPE_VARIABLE, 'length': 'cveIdLength', 'name': 'cveId' },
            { 'type': TYPE_UINT32, 'name': 'bugtraqIdLength' },
            { 'type': TYPE_VARIABLE, 'length': 'bugtraqLength', 'name': 'bugtraqId' } ],
        'category': u'VULNERABILITY' },

    # 107
    RECORD_RNA_CHANGE_CLIENT_APP_UPDATE: {
        'name': u'Client Application Update',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_HOST_CLIENT_APPLICATION_50, 'name': 'client'}],
        'category': u'RNA' },

    # 109
    RECORD_RNA_WEB_APPLICATION_PAYLOAD: {
        'name': u'Web Application',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'PAYLOAD' },

    # 110
    RECORD_INTRUSION_EXTRA_DATA: {
        'name': u'Intrusion Event Extra Data',
        'attributes': [ { 'block': BLOCK_EVENT_EXTRA_DATA } ],
        'category': u'EXTRA DATA' },

    # 111
    METADATA_INTRUSION_EXTRA_DATA: {
        'name': u'Intrusion Event Extra Data Metadata',
        'attributes': [ { 'block': BLOCK_EVENT_EXTRA_DATA_METADATA } ],
        'category': u'EXTRA DATA TYPE' },

    # 112
    RECORD_CORRELATION_EVENT: {
        'name': u'Correlation Event',
        'attributes': [ { 'block': BLOCK_CORRELATION_EVENT_54 } ],
        'category': u'POLICY' },

    # 115
    METADATA_SECURITY_ZONE_NAME: {
        'name': u'Security Zone Name Metadata',
        'attributes': [ { 'block': BLOCK_UUID_STRING } ],
        'category': u'ZONE' },

    # 116
    METADATA_INTERFACE_NAME: {
        'name': u'Interface Name Metadata',
        'attributes': [ { 'block': BLOCK_UUID_STRING } ],
        'category': u'INTERFACE' },

    # 117
    METADATA_ACCESS_CONTROL_POLICY_NAME: {
        'name': u'Access Control Policy Name Metadata',
        'attributes': [ { 'block': BLOCK_UUID_STRING } ],
        'category': u'FIREWALL POLICY' },

    # 118
    METADATA_INTRUSION_POLICY_NAME: {
        'name': u'Intrusion Policy Name Metadata',
        'attributes': [ { 'block': BLOCK_UUID_STRING } ],
        'category': u'INTRUSION POLICY' },

    # 119
    METADATA_ACCESS_CONTROL_RULE_ID: {
        'name': u'Access Control Rule ID Metadata',
        'attributes': [ { 'block': BLOCK_ACCESS_CONTROL_RULE } ],
        'category': u'FIREWALL RULE' },

    # 120
    METADATA_ACCESS_CONTROL_RULE_ACTION: {
        'name': u'Access Control Rule Action Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FIREWALL RULE ACTION' },

    # 121
    METADATA_URL_CATEGORY: {
        'name': u'URL Category Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FIREWALL URL CATEGORY' },

    # 122
    METADATA_URL_REPUTATION: {
        'name': u'URL Reputation Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FIREWALL URL REPUTATION' },

    # 123
    METADATA_SENSOR: {
        'name': u'Managed Device Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SENSOR' },

    # 124
    METADATA_ACCESS_CONTROL_POLICY_RULE_REASON: {
        'name': u'Access Control Policy Rule Reason Data',
        'attributes': [ { 'block': BLOCK_ACCESS_CONTROL_POLICY_RULE_REASON_60 } ],
        'category': u'FIREWALL RULE REASON' },

    # 125
    RECORD_MALWARE_EVENT: {
        'name': u'Malware Event Record',
        'attributes': [ { 'block': BLOCK_MALWARE_EVENT_60 }],
        'category': u'MALWARE EVENT' },

    # 127
    METADATA_FIREAMP_CLOUD_NAME: {
        'name': u'Cisco AMP Cloud Name Metadata',
        'attributes': [ { 'block': BLOCK_UUID_STRING } ],
        'category': u'FIREAMP CLOUD' },

    # 128
    METADATA_FIREAMP_EVENT_TYPE: {
        'name': u'Malware Event Type Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'MALWARE EVENT TYPE' },

    # 129
    METADATA_FIREAMP_EVENT_SUBTYPE: {
        'name': u'Malware Event Subtype Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'MALWARE EVENT SUBTYPE' },

    # 130
    METADATA_FIREAMP_DETECTOR_TYPE: {
        'name': u'AMP for Endpoints Detector Type Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'MALWARE DETECTOR TYPE' },

    # 131
    METADATA_FIREAMP_FILE_TYPE: {
        'name': u'AMP for Endpoints File Type Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'MALWARE FILE TYPE' },

    # 132
    METADATA_SECURITY_CONTEXT_NAME: {
        'name': u'Security Context Name',
        'attributes': [
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'block': BLOCK_STRING, 'name': 'name' }],
        'category': u'CONTEXT ID' },

    # 140
    RECORD_RULE_DOCUMENTATION_DATA: {
        'name': u'Rule Documentation Data',
        'attributes': [ { 'block': BLOCK_RULE_DOCUMENTATION_DATA_52 } ],
        'category': u'IPS RULE DOC' },

    # 145
    METADATA_ACCESS_CONTROL_POLICY: {
        'name': u'Access Control Policy Metadata',
        'attributes': [ { 'block': BLOCK_ACCESS_CONTROL_POLICY_METADATA } ],
        'category': u'ACCESS CONTROL POLICY' },

    # 146
    METADATA_PREFILTER_POLICY: {
        'name': u'Prefilter Policy Metadata',
        'attributes': [ { 'block': BLOCK_ACCESS_CONTROL_POLICY_METADATA } ],
        'category': u'ACCESS CONTROL POLICY' },

    # 147
    METADATA_TUNNEL_OR_PREFILTER_RULE: {
        'name': u'Tunnel or Prefilter Rule Metadata',
        'attributes': [ { 'block': BLOCK_ACCESS_CONTROL_POLICY_METADATA } ],
        'category': u'ACCESS CONTROL POLICY' },

    # 160 - Big difference between version 6 & 6.1
    # Version 6 points at BLOCK_IOC_STATE_53 and is for IOC State
    # where as 6.1 is IOC Set
    RECORD_RNA_IOC_SET: {
        'name': u'Host IOC Set Messages',
        'attributes': [
            { 'discovery': True },
            { 'block': BLOCK_INTEGER, 'name': 'id' }],
        'category': u'RNA' },

    # 161
    METADATA_IOC_NAME: {
        'name': u'IOC Name Data',
        'attributes': [ { 'block': BLOCK_IOC_NAME_53 } ],
        'category': u'IOC' },

    # 170
    VPN_LOGIN_EVENT: {
        'name': u'VPN Login Data',
        'attributes': [ { 'block': BLOCK_USER_LOGIN_INFORMATION_DATA_50 } ],
        'category': u'VPN LOGIN' },

    # 260
    METADATA_ICMP_TYPE: {
        'name': u'ICMP Type Data',
        'attributes': [ { 'block': BLOCK_ICMP_TYPE_DATA } ],
        'category': u'ICMP TYPE' },

    # 270
    METADATA_ICMP_CODE: {
        'name': u'ICMP Code Data',
        'attributes': [ { 'block': BLOCK_ICMP_CODE_DATA } ],
        'category': u'ICMP CODE' },

    # 280
    METADATA_SECURITY_INTELLIGENCE_CATEGORY_DISCOVERY: {
        'name': u'Security Intelligence Category Metadata',
        'attributes': [ { 'block': BLOCK_IP_REPUTATION_CATEGORY } ],
        'category': u'SECURITY INTELLIGENCE CATEGORY' },

    # 281
    METADATA_SECURITY_INTELLIGENCE_SRCDEST: {
        'name': u'Security Intelligence Source/Destination ',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SECURITY INTELLIGENCE SOURCE/DEST' },

    # 282
    METADATA_SECURITY_INTELLIGENCE_CATEGORY_GENERAL: {
        'name': u'Security Intelligence Category Metadata',
        'attributes': [
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'block': BLOCK_STRING, 'name': 'name' }],
        'category': u'SECURITY INTELLIGENCE CATEGORY' },

    # 300
    METADATA_REALM: {
        'name': u'Realm Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'REALM DATA' },

    # 301
    RECORD_ENDPOINT_PROFILE_DATA: {
        'name': u'Endpoint Profile',
        'attributes': [ { 'block': BLOCK_ENDPOINT_PROFILE_60 } ],
        'category': u'ENDPOINT PROFILE' },

    # 302
    METADATA_SECURITY_GROUP: {
        'name': u'Security Group Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SECURITY GROUP' },

    # 320
    METADATA_DNS_RECORD: {
        'name': u'DNS Record Type Metadata',
        'attributes': [ { 'block': BLOCK_ID_NAME_DESCRIPTION } ],
        'category': u'DNS' },

    # 321
    METADATA_DNS_RESPONSE: {
        'name': u'DNS Response Type Metadata',
        'attributes': [ { 'block': BLOCK_ID_NAME_DESCRIPTION } ],
        'category': u'DNS' },

    # 322
    METADATA_SINKHOLE: {
        'name': u'Sinkhole Metadata',
        'attributes': [ { 'block': BLOCK_UUID_STRING } ],
        'category': u'SINKHOLE' },

    # 350
    METADATA_NETMAP_DOMAIN: {
        'name': u'Netmap Domain Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'NETMAP DOMAIN' },

    # 400
    RECORD_INTRUSION_EVENT: {
        'name': u'Intrusion Event',
        'attributes': [ { 'block': BLOCK_INTRUSION_EVENT_60 } ],
        'category': u'IPS EVENT' },

    # 500
    RECORD_FILELOG_EVENT: {
        'name': u'File Event',
        'attributes': [ { 'block': BLOCK_FILE_EVENT_60 } ],
        'category': u'FILELOG EVENT' },

    # 502
    RECORD_FILELOG_MALWARE_EVENT: {
        'name': u'File Malware Event',
        'attributes': [ { 'block': BLOCK_FILE_EVENT_60 } ],
        'category': u'FILELOG MALWARE EVENT' },

    # 510
    METADATA_FILELOG_FILE_TYPE: {
        'name': u'File Type ID Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FILELOG FILE TYPE' },

    # 511
    METADATA_FILELOG_SHA: {
        'name': u'File Event SHA Hash',
        'attributes': [ { 'block': BLOCK_FILE_EVENT_SHA_HASH_53 } ],
        'category': u'FILELOG SHA' },

    # 515
    METADATA_FILELOG_STORAGE: {
        'name': u'Filelog Storage Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FILELOG STORAGE' },

    # 516
    METADATA_FILELOG_SANDBOX: {
        'name': u'Filelog Sandbox Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FILELOG SANDBOX' },

    # 517
    METADATA_FILELOG_SPERO: {
        'name': u'Filelog Spero Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FILELOG SPERO' },

    # 518
    METADATA_FILELOG_ARCHIVE: {
        'name': u'Filelog Archive Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FILELOG ARCHIVE' },

    # 519
    METADATA_FILELOG_STATIC_ANALYSIS: {
        'name': u'Filelog Static Analysis Metadata',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'FILELOG STATIC ANALYSIS' },

    # 520
    METADATA_GEOLOCATION: {
        'name': u'Geolocation Data',
        'attributes': [ { 'block': BLOCK_GEOLOCATION_52 } ],
        'category': u'GEOLOCATION' },

    # 530
    METADATA_FILE_POLICY_NAME: {
        'name': u'File Policy Name',
        'attributes': [
            # Documentation diagram *and* text wrong!
            { 'type': TYPE_UINT32, 'name': 'blockType' },
            { 'type': TYPE_UINT32, 'name': 'blockLength' },
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'block': BLOCK_STRING, 'name': 'name' }],
        'category': u'FILE POLICY NAME' },

    # 600
    METADATA_SSL_POLICY: {
        'name': u'SSL Policy Name',
        'attributes': [
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'block': BLOCK_STRING, 'name': 'name' }],
        'category': u'SSL POLICY NAME' },

    # 601
    METADATA_SSL_RULE_ID: {
        'name': u'SSL Rule ID',
        'attributes': [
            { 'type': TYPE_UINT128, 'name': 'revision' },
            { 'type': TYPE_UINT32, 'name': 'id' },
            { 'block': BLOCK_STRING, 'name': 'name' }],
        'category': u'SSL RULE ID' },

    # 602
    METADATA_SSL_CIPHER_SUITE: {
        'name': u'SSL Cipher Suite',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SSL CIPHER SUITE' },

    # 604
    METADATA_SSL_VERSION: {
        'name': u'SSL Version',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SSL VERSION' },

    # 605
    METADATA_SSL_SERVER_CERTIFICATE_STATUS: {
        'name': u'SSL Server Certificate Status',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SSL SERVER CERT STATUS' },

    # 606
    METADATA_SSL_ACTUAL_ACTION: {
        'name': u'SSL Actual Action',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SSL ACTION' },

    # 607
    METADATA_SSL_EXPECTED_ACTION: {
        'name': u'SSL Expected Action',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SSL ACTION' },

    # 608
    METADATA_SSL_FLOW_STATUS: {
        'name': u'SSL Flow Status',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SSL FLOW STATUS' },

    # 613
    METADATA_SSL_URL_CATEGORY: {
        'name': u'SSL URL Category',
        'attributes': [ { 'block': BLOCK_METADATA_ID_LENGTH_NAME } ],
        'category': u'SSL URL CATEGORY' },

    # 614
    METADATA_SSL_CERTIFICATE_DETAILS_DATA: {
        'name': u'SSL Certificate Details Data',
        'attributes': [ { 'block': BLOCK_SSL_CERTIFICATION_DETAILS_54 } ],
        'category': u'SSL CERTIFICATE DETAILS' },

    # 700
    METADATA_RECORD_NETWORK_ANALYSIS_POLICY: {
        'name': u'Network Analysis Policy',
        'attributes': [
            # Documentation diagram *and* text wrong!
            { 'type': TYPE_UINT32, 'name': 'blockType' },
            { 'type': TYPE_UINT32, 'name': 'blockLength' },
            { 'type': TYPE_UUID, 'name': 'uuid' },
            { 'block': BLOCK_STRING, 'name': 'name' }],
        'category': u'NAP NAME'}
}
