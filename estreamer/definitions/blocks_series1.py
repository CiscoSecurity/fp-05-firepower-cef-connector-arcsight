
#********************************************************************
#      File:    blocks_series1.py
#      Author:  Sam Strachan
#
#      Description:
#       Series 1 blocks
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

from estreamer.definitions.core import TYPE_BYTE
from estreamer.definitions.core import TYPE_UINT16
from estreamer.definitions.core import TYPE_UINT32
from estreamer.definitions.core import TYPE_UINT64
from estreamer.definitions.core import TYPE_UINT128
from estreamer.definitions.core import TYPE_UINT160
from estreamer.definitions.core import TYPE_UINT256
from estreamer.definitions.core import TYPE_VARIABLE
from estreamer.definitions.core import TYPE_UUID
from estreamer.definitions.core import TYPE_IPV4
from estreamer.definitions.core import TYPE_IPV6
from estreamer.definitions.core import TYPE_MAC

BLOCK_AUTO = -1

# Series 1 data block
BLOCK_STRING = 0
BLOCK_SUBSERVER = 1
BLOCK_PROTOCOL = 4
BLOCK_INTEGER = 7
BLOCK_BLOB = 10
BLOCK_VLAN_DATA = 14
BLOCK_STRING_INFORMATION = 35
BLOCK_SERVER_BANNER = 37
BLOCK_ATTRIBUTE_LIST_ITEM_DATA = 39
BLOCK_OPERATING_SYSTEM_DATA_35 = 53
BLOCK_ATTRIBUTE_DEFINITION_47 = 55
BLOCK_USER_PROTOCOL = 57
BLOCK_USER_CLIENT_APPLICATION_LIST = 60
BLOCK_MAC_ADDRESS_SPECIFICATION = 63
BLOCK_FIX_DATA = 67
BLOCK_USER_SERVER = 76
BLOCK_USER_SERVER_LIST = 77
BLOCK_USER_HOSTS_47 = 78
BLOCK_USER_VULNERABILITY_CHANGE_47 = 80
BLOCK_USER_CRITICALITY_CHANGE_47 = 81
BLOCK_USER_ATTRIBUTE_VALUE_47 = 82
BLOCK_USER_PROTOCOL_LIST_47 = 83
BLOCK_HOST_VULNERABILITY_49 = 85
BLOCK_IDENTITY_DATA = 94
BLOCK_HOST_MAC_ADDRESS_49 = 95
BLOCK_HOST_SERVER_DATA_41 = 103
BLOCK_GENERIC_SCAN_RESULTS_DATA_41 = 108
BLOCK_SCAN_VULNERABILITY_DATA_41 = 109
BLOCK_FULL_HOST_CLIENT_APPLICATION_50 = 112
BLOCK_SERVER_INFORMATION_50 = 117
BLOCK_USER_INFORMATION_DATA_50 = 120
BLOCK_HOST_CLIENT_APPLICATION_50 = 122
BLOCK_WEB_APPLICATION_DATA_50 = 123
BLOCK_USER_VULNERABILITY_DATA_50 = 124
BLOCK_USER_LOGIN_INFORMATION_54 = 127
BLOCK_OPERATING_SYSTEM_FINGERPRINT_51 = 130
BLOCK_MOBILE_DEVICE_INFORMATION_51 = 131
BLOCK_USER_PRODUCT_DATA_51 = 134
BLOCK_CONNECTION_CHUNK_511 = 136
BLOCK_USER_CLIENT_APPLICATION_511 = 138
BLOCK_HOST_PROFILE_DATA_52 = 139
BLOCK_IP_ADDRESS_RANGE_DATA_52 = 141
BLOCK_SCAN_RESULT_DATA_52 = 142
BLOCK_ATTRIBUTE_ADDRESS_52 = 146
BLOCK_IOC_STATE_53 = 150
BLOCK_INTRUSION_IMPACT_ALERT_53 = 153
BLOCK_CORRELATION_EVENT_54 = 156
BLOCK_USER_LOGIN_INFORMATION_60 = 159
BLOCK_CONNECTION_STATISTICS_60 = 160
BLOCK_CONNECTION_STATISTICS_61 = 163
BLOCK_USER_LOGIN_INFORMATION_61 = 165
BLOCK_USER_LOGIN_INFORMATION_DATA_50 = 167

# Custom data blocks
BLOCK_METADATA_ID_LENGTH_NAME = 10000

# Blocks should be defined in traits as:
#   1. { 'block': BLOCK_AUTO, 'name': 'theName' }
#   2. { 'block': BLOCK_STRING, 'name': 'description' }
#   3. { 'block': BLOCK_AUTO }
#   4. { 'block': BLOCK_USER_LOGIN_INFORMATION_61 }
#
# Numbers 3 & 4 put the block attributes directly into the container. This is
# potentially risky as far as naming collisions go.


BLOCKS_SERIES_1 = {
    # 0
    BLOCK_STRING: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        # Adjustment is required because it's the *block* length and not the
        # string length. -8 cancels out the two uint32s
        { 'adjustment': -8, 'type': TYPE_VARIABLE, 'length': 'blockLength', 'name': 'data'}],

    # 1
    BLOCK_SUBSERVER: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'block': BLOCK_STRING, 'name': 'subServerName' },
        { 'block': BLOCK_STRING, 'name': 'vendor' },
        { 'block': BLOCK_STRING, 'name': 'version' }],

    # 4 Series 1
    BLOCK_PROTOCOL: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'protocol'}],

    # 7
    BLOCK_INTEGER: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'value'}],

    # 10
    BLOCK_BLOB: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        # Adjustment is required because it's the *block* length and not the
        # blob length. -8 cancels out the two uint32s
        { 'adjustment': -8, 'type': TYPE_VARIABLE, 'length': 'blockLength', 'name': 'data'}],

    # 14
    BLOCK_VLAN_DATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'id' },
        { 'type': TYPE_BYTE, 'name': 'type' },
        { 'type': TYPE_BYTE, 'name': 'priority' } ],

    # 35
    BLOCK_STRING_INFORMATION: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'block': BLOCK_STRING, 'name': 'value' }],

    # 37
    BLOCK_SERVER_BANNER: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_BYTE, 'name': 'protocol' },
        { 'block': BLOCK_BLOB, 'name': 'data' } ],

    # 39
    BLOCK_ATTRIBUTE_LIST_ITEM_DATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'block': BLOCK_STRING, 'name': 'name' }],

    # 57
    BLOCK_USER_PROTOCOL: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'list': BLOCK_MAC_ADDRESS_SPECIFICATION, 'name': 'macRanges' },
        { 'type': TYPE_BYTE, 'name': 'protocolType' },
        { 'type': TYPE_UINT16, 'name': 'protocol' } ],

    # 60
    BLOCK_USER_CLIENT_APPLICATION_LIST: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'list': BLOCK_USER_CLIENT_APPLICATION_511, 'name': 'list' } ],

    # 63
    BLOCK_MAC_ADDRESS_SPECIFICATION: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_MAC, 'name': 'macAddress' } ],

    # 67
    BLOCK_FIX_DATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'id' } ],

    # 76
    BLOCK_USER_SERVER: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'protocol' } ],

    # 77
    BLOCK_USER_SERVER_LIST: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'list': BLOCK_USER_SERVER, 'name': 'macRanges' } ],

    # 78
    BLOCK_USER_HOSTS_47: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'list': BLOCK_MAC_ADDRESS_SPECIFICATION, 'name': 'macRanges' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' } ],

    # 80
    BLOCK_USER_VULNERABILITY_CHANGE_47: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        # Documentation conflict between diagram & table
        { 'type': TYPE_UINT32, 'name': 'type' },
        { 'list': BLOCK_USER_VULNERABILITY_DATA_50, 'name': 'list' } ],

    # 81
    BLOCK_USER_CRITICALITY_CHANGE_47: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'criticality' } ],

    # 82
    BLOCK_USER_ATTRIBUTE_VALUE_47: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'attributeId' },
        { 'block': BLOCK_BLOB, 'name': 'value' } ],

    # 83
    BLOCK_USER_PROTOCOL_LIST_47: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'list': BLOCK_USER_PROTOCOL, 'name': 'list' } ],

    # 85
    BLOCK_HOST_VULNERABILITY_49: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'vulnerabilityId' },
        { 'type': TYPE_BYTE, 'name': 'invalidFlags' },
        { 'type': TYPE_UINT32, 'name': 'type'}],

    # 94
    BLOCK_IDENTITY_DATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'type': TYPE_UUID, 'name': 'uuid' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'type': TYPE_UINT32, 'name': 'serverMapId'}],

    # 95
    BLOCK_HOST_MAC_ADDRESS_49: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_BYTE, 'name': 'ttl' },
        { 'type': TYPE_MAC, 'name': 'address' },
        { 'type': TYPE_BYTE, 'name': 'primary' },
        { 'type': TYPE_UINT32, 'name': 'lastSeen'}],

    # 103
    BLOCK_HOST_SERVER_DATA_41: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT32, 'name': 'hits' },
        { 'type': TYPE_UINT32, 'name': 'lastUsed' },
        { 'list': BLOCK_SERVER_INFORMATION_50, 'name': 'serverInformation' },
        { 'type': TYPE_UINT32, 'name': 'confidence' },
        { 'list': BLOCK_WEB_APPLICATION_DATA_50, 'name': 'webApplication' }],
    # Documentation says these are supposed to follow webApplication in hostServer
    # but this appears to be a lie.
    #   { 'name': 'webApplicationBlockLength', 'type': TYPE_UINT32 }, \
    #   { 'name': 'webApplicationData',
    #     'type': TYPE_VARIABLE, 'length': 'webApplicationBlockLength' } \

    # 108
    BLOCK_GENERIC_SCAN_RESULTS_DATA_41: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'block': BLOCK_STRING, 'name': 'subServer' },
        { 'block': BLOCK_STRING, 'name': 'value' },
        { 'block': BLOCK_STRING, 'name': 'subServerUnformatted' },
        { 'block': BLOCK_STRING, 'name': 'valueUnformatted' } ],

    # 109
    BLOCK_SCAN_VULNERABILITY_DATA_41: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'block': BLOCK_STRING, 'name': 'id' },
        { 'block': BLOCK_STRING, 'name': 'name' },
        { 'block': BLOCK_STRING, 'name': 'description' },
        { 'block': BLOCK_STRING, 'name': 'nameClean' },
        { 'block': BLOCK_STRING, 'name': 'descriptionClean' },
        { 'list': BLOCK_INTEGER, 'name': 'bugtraqIds' },
        { 'list': BLOCK_STRING_INFORMATION, 'name': 'cveIds' } ],

    # 112
    BLOCK_FULL_HOST_CLIENT_APPLICATION_50: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'hits' },
        { 'type': TYPE_UINT32, 'name': 'lastUsed' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'block': BLOCK_STRING, 'name': 'version' },
        { 'list': BLOCK_WEB_APPLICATION_DATA_50, 'name': 'webApplication' },
        { 'list': BLOCK_HOST_VULNERABILITY_49, 'name': 'vulnerability' }],

    # 117
    BLOCK_SERVER_INFORMATION_50: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'block': BLOCK_STRING, 'name': 'vendor' },
        { 'block': BLOCK_STRING, 'name': 'version' },
        { 'type': TYPE_UINT32, 'name': 'lastUsed' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'list': BLOCK_SUBSERVER, 'name': 'subServers' }],

    # 120
    BLOCK_USER_INFORMATION_DATA_50: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'block': BLOCK_STRING, 'name': 'username' },
        { 'type': TYPE_UINT32, 'name': 'protocol' },
        { 'block': BLOCK_STRING, 'name': 'firstName' },
        { 'block': BLOCK_STRING, 'name': 'lastName' },
        { 'block': BLOCK_STRING, 'name': 'email' },
        { 'block': BLOCK_STRING, 'name': 'department' },
        { 'block': BLOCK_STRING, 'name': 'phone' }],

    # 121
    BLOCK_USER_LOGIN_INFORMATION_DATA_50: [
        { 'type': TYPE_UINT32, 'name': 'loginBlockType' },
        { 'type': TYPE_UINT32, 'name': 'loginBlockLength' },
        { 'type': TYPE_UINT32, 'name': 'timeStamp' },
        { 'type': TYPE_UINT32, 'name': 'ipv4Address' },
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'block': BLOCK_STRING, 'name': 'username' },
        { 'block': BLOCK_STRING, 'name': 'domain' },
        { 'block': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'realmId' },
        { 'type': TYPE_UINT32, 'name': 'endpointProfileId' },
        { 'type': TYPE_UINT32, 'name': 'securityGroupId' },
        { 'type': TYPE_UINT32, 'name': 'protocol' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'portRangeStart' },
        { 'type': TYPE_UINT16, 'name': 'portRangeEnd' },
        { 'type': TYPE_UINT32, 'name': 'email' },
        { 'type': TYPE_UINT32, 'name': 'emailSizeBytes' },
        { 'type': TYPE_IPV6, 'name': 'ipv6Address' },
        { 'type': BLOCK_STRING, 'name': 'ipLocation' },
        { 'type': TYPE_UINT16, 'name': 'loginType' },
        { 'type': TYPE_UINT16, 'name': 'authType' },
        { 'type': TYPE_UINT32, 'name': 'reportedByType' },
        { 'type': TYPE_UINT16, 'name': 'reportedByLength' },
        { 'block': BLOCK_STRING, 'name': 'reportedBy' },
        { 'block': BLOCK_STRING, 'name': 'description' },
        { 'block': BLOCK_STRING, 'name': 'VPNSessionBlockType' },
        { 'block': BLOCK_STRING, 'name': 'VPNSessionBlockLength' },
        { 'block': BLOCK_STRING, 'name': 'VPNSessionData' }],


    # 122
    BLOCK_HOST_CLIENT_APPLICATION_50: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'hits' },
        { 'type': TYPE_UINT32, 'name': 'lastUsed' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'type': TYPE_UINT32, 'name': 'applicationProto' },
        { 'block': BLOCK_STRING, 'name': 'version' },
        { 'list': BLOCK_WEB_APPLICATION_DATA_50, 'name': 'webApplication' }],

    # 123
    BLOCK_WEB_APPLICATION_DATA_50: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' }],

    # 124
    BLOCK_USER_VULNERABILITY_DATA_50: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'type': TYPE_UINT32, 'name': 'vulnerabilityId' },
        { 'type': TYPE_UUID, 'name': 'thirdPartyVulnerabilityUuid' },
        { 'block': BLOCK_STRING, 'name': 'description' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'applicationProtocolId' },
        { 'block': BLOCK_STRING, 'name': 'version' } ],

    # 127
    BLOCK_USER_LOGIN_INFORMATION_54: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'timestamp' },
        { 'type': TYPE_IPV4, 'name': 'ipv4Address' },
        { 'block': BLOCK_STRING, 'name': 'username' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'block': BLOCK_STRING, 'name': 'email' },
        { 'type': TYPE_IPV6, 'name': 'ipv6Address' },
        { 'type': TYPE_BYTE, 'name': 'loginType' },
        { 'block': BLOCK_STRING, 'name': 'reportedBy' }],

    # 130
    BLOCK_OPERATING_SYSTEM_FINGERPRINT_51: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UUID, 'name': 'uuid' },
        { 'type': TYPE_UINT32, 'name': 'type' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'type': TYPE_UINT32, 'name': 'lastSeen' },
        { 'type': TYPE_BYTE, 'name': 'ttlDifference' },
        { 'list': BLOCK_MOBILE_DEVICE_INFORMATION_51, 'name': 'mobileDevice' }],

    # 131
    BLOCK_MOBILE_DEVICE_INFORMATION_51: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'block': BLOCK_STRING, 'name': 'string' },
        { 'type': TYPE_UINT32, 'name': 'lastSeen' },
        { 'type': TYPE_UINT32, 'name': 'mobile' },
        { 'type': TYPE_UINT32, 'name': 'jailbroken'}],

    # 134
    BLOCK_USER_PRODUCT_DATA_51: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'sourceId' },
        { 'type': TYPE_UINT32, 'name': 'sourceType' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'type': TYPE_UINT32, 'name': 'dropUserProduct' },
        { 'block': BLOCK_STRING, 'name': 'vendor' },
        { 'block': BLOCK_STRING, 'name': 'product' },
        { 'block': BLOCK_STRING, 'name': 'version' },
        { 'type': TYPE_UINT32, 'name': 'softwareId' },
        { 'type': TYPE_UINT32, 'name': 'serverId' },
        { 'type': TYPE_UINT32, 'name': 'vendorId' },
        { 'type': TYPE_UINT32, 'name': 'productId' },
        { 'block': BLOCK_STRING, 'name': 'versionMajor' },
        { 'block': BLOCK_STRING, 'name': 'versionMinor' },
        { 'block': BLOCK_STRING, 'name': 'revision' },
        { 'block': BLOCK_STRING, 'name': 'toVersionMajor' },
        { 'block': BLOCK_STRING, 'name': 'toVersionMinor' },
        { 'block': BLOCK_STRING, 'name': 'toRevision' },
        { 'block': BLOCK_STRING, 'name': 'build' },
        { 'block': BLOCK_STRING, 'name': 'patch' },
        { 'block': BLOCK_STRING, 'name': 'extension' },
        { 'type': TYPE_UUID, 'name': 'osUuid' },
        { 'block': BLOCK_STRING, 'name': 'device' },
        { 'type': TYPE_BYTE, 'name': 'mobile' },
        { 'type': TYPE_BYTE, 'name': 'jailbroken' },
        { 'list': BLOCK_FIX_DATA, 'name': 'fixes' } ],

    # 136
    BLOCK_CONNECTION_CHUNK_511: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_IPV4, 'name': 'initiatorIpAddress' },
        { 'type': TYPE_IPV4, 'name': 'responderIpAddress' },
        { 'type': TYPE_UINT32, 'name': 'startTime' },
        { 'type': TYPE_UINT32, 'name': 'applicationProto' },
        { 'type': TYPE_UINT16, 'name': 'responderPort' },
        { 'type': TYPE_BYTE, 'name': 'protocol' },
        { 'type': TYPE_BYTE, 'name': 'connectionType' },
        { 'type': TYPE_IPV4, 'name': 'netflowDetectorIpAddress' },
        { 'type': TYPE_UINT64, 'name': 'packetsSent' },
        { 'type': TYPE_UINT64, 'name': 'packetsReceived' },
        { 'type': TYPE_UINT64, 'name': 'bytesSent' },
        { 'type': TYPE_UINT64, 'name': 'bytesReceived' },
        { 'type': TYPE_UINT32, 'name': 'connections' }
    ],

    # 138
    BLOCK_USER_CLIENT_APPLICATION_511: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'list': BLOCK_IP_ADDRESS_RANGE_DATA_52, 'name': 'ipRanges' },
        { 'type': TYPE_UINT32, 'name': 'applicationProtocolId' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'block': BLOCK_STRING, 'name': 'version' },
        { 'type': TYPE_UINT32, 'name': 'payloadType' },
        { 'type': TYPE_UINT32, 'name': 'webApplicationId' },
    ],

    # 139
    BLOCK_HOST_PROFILE_DATA_52: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockString' },
        { 'type': TYPE_IPV6, 'name': 'ipAddress' }, #eStreamer spec uint8[16]
        { 'type': TYPE_BYTE, 'name': 'hops' },
        { 'type': TYPE_BYTE, 'name': 'primarySecondary' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'serverFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'clientFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'smbFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'dhcpFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'mobileDeviceFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'ipv6ServerFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'ipv6ClientFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'ipv6DhcpFingerprints' },
        { 'list': BLOCK_OPERATING_SYSTEM_FINGERPRINT_51, 'name': 'userAgentFingerprints' },
        { 'list': BLOCK_HOST_SERVER_DATA_41, 'name': 'tcpServer' },
        { 'list': BLOCK_HOST_SERVER_DATA_41, 'name': 'udpServer' },
        { 'list': BLOCK_PROTOCOL, 'name': 'networkProtocol' },
        { 'list': BLOCK_PROTOCOL, 'name': 'transportProtocol' },
        { 'list': BLOCK_HOST_MAC_ADDRESS_49, 'name': 'hostMacAddress' },
        { 'type': TYPE_UINT32, 'name': 'hostLastSeen' },
        { 'type': TYPE_UINT32, 'name': 'hostType' },
        { 'type': TYPE_BYTE, 'name': 'mobile' },
        { 'type': TYPE_BYTE, 'name': 'jailbroken' },
        { 'type': TYPE_BYTE, 'name': 'vlanPresence' },
        { 'type': TYPE_UINT16, 'name': 'vlanId' },
        { 'type': TYPE_BYTE, 'name': 'vlanType' },
        { 'type': TYPE_BYTE, 'name': 'vlanPriority' },
        { 'list': BLOCK_FULL_HOST_CLIENT_APPLICATION_50, 'name': 'clientApplications' },
        { 'block': BLOCK_STRING, 'name': 'netbios' }],

    # 141
    BLOCK_IP_ADDRESS_RANGE_DATA_52: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_IPV6, 'name': 'start' },
        { 'type': TYPE_IPV6, 'name': 'finish' } ],

    # 142
    BLOCK_SCAN_RESULT_DATA_52: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'scanType' },
        { 'type': TYPE_IPV6, 'name': 'ipAddress' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'type': TYPE_UINT16, 'name': 'flag' },
        { 'list': BLOCK_SCAN_VULNERABILITY_DATA_41, 'name': 'vulnerabilities' },
        { 'list': BLOCK_GENERIC_SCAN_RESULTS_DATA_41, 'name': 'scanResults' },
        { 'list': BLOCK_USER_PRODUCT_DATA_51, 'name': 'userProducts' } ],

    # 150
    BLOCK_IOC_STATE_53: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'iocIdNumber' },
        { 'type': TYPE_BYTE, 'name': 'disabled' },
        { 'type': TYPE_UINT32, 'name': 'firstSeen' },
        { 'type': TYPE_UINT32, 'name': 'firstEventId' },
        { 'type': TYPE_UINT32, 'name': 'firstDeviceId' },
        { 'type': TYPE_UINT16, 'name': 'firstInstanceId' },
        { 'type': TYPE_UINT32, 'name': 'firstConnectionTime' },
        { 'type': TYPE_UINT16, 'name': 'firstCounter' },
        { 'type': TYPE_UINT32, 'name': 'lastSeen' },
        { 'type': TYPE_UINT32, 'name': 'lastEventId' },
        { 'type': TYPE_UINT16, 'name': 'lastInstanceId' },
        { 'type': TYPE_UINT32, 'name': 'lastConnectionTime' },
        { 'type': TYPE_UINT16, 'name': 'lastCounter'}],

    # 153
    BLOCK_INTRUSION_IMPACT_ALERT_53: [
        # Documentation diagram incorrect! See text
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'eventId' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UINT32, 'name': 'eventSecond' },
        { 'type': TYPE_UINT32, 'name': 'impact' },
        { 'type': TYPE_IPV6, 'name': 'sourceIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'destinationIpAddress' },
        { 'block': BLOCK_STRING, 'name': 'description' }],

    # 156
    BLOCK_CORRELATION_EVENT_54: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UINT32, 'name': 'correlationEventSecond' },
        { 'type': TYPE_UINT32, 'name': 'eventId' },
        { 'type': TYPE_UINT32, 'name': 'policyId' },
        { 'type': TYPE_UINT32, 'name': 'ruleId' },
        { 'type': TYPE_UINT32, 'name': 'priority' },
        { 'block': BLOCK_STRING, 'name': 'eventDescription' },
        { 'type': TYPE_BYTE, 'name': 'eventType' },
        { 'type': TYPE_UINT32, 'name': 'eventDeviceId' },
        { 'type': TYPE_UINT32, 'name': 'signatureId' },
        { 'type': TYPE_UINT32, 'name': 'signatureGeneratorId' },
        { 'type': TYPE_UINT32, 'name': 'triggerEventSecond' },
        { 'type': TYPE_UINT32, 'name': 'triggerEventMicrosecond' },
        { 'type': TYPE_UINT32, 'name': 'deviceEventId' },
        { 'type': TYPE_UINT32, 'name': 'eventDefinedMask' },
        { 'type': TYPE_BYTE, 'name': 'eventImpactFlags' },
        { 'type': TYPE_BYTE, 'name': 'ipProtocol' },
        { 'type': TYPE_UINT16, 'name': 'networkProtocol' },
        { 'type': TYPE_IPV4, 'name': 'sourceIp' }, # No longer used
        { 'type': TYPE_BYTE, 'name': 'sourceHostType' },
        { 'type': TYPE_UINT16, 'name': 'sourceVlanId' },
        { 'type': TYPE_UUID, 'name': 'sourceOperatingSystemFingerprintUuid' },
        { 'type': TYPE_UINT16, 'name': 'sourceCriticality' },
        { 'type': TYPE_UINT32, 'name': 'sourceUserId' },
        { 'type': TYPE_UINT16, 'name': 'sourcePort' },
        { 'type': TYPE_UINT32, 'name': 'sourceServerId' },
        { 'type': TYPE_IPV4, 'name': 'destinationIp' }, # No longer used
        { 'type': TYPE_BYTE, 'name': 'destinationHostType' },
        { 'type': TYPE_UINT16, 'name': 'destinationVlanId' },
        { 'type': TYPE_UUID, 'name': 'destinationOperatingSystemFingerprintUuid' },
        { 'type': TYPE_UINT16, 'name': 'destinationCriticality' },
        { 'type': TYPE_UINT32, 'name': 'destinationUserId' },
        { 'type': TYPE_UINT16, 'name': 'destinationPort' },
        { 'type': TYPE_UINT32, 'name': 'destinationServerId' },
        { 'type': TYPE_BYTE, 'name': 'impact' },
        { 'type': TYPE_BYTE, 'name': 'blocked' },
        { 'type': TYPE_UUID, 'name': 'intrusionPolicy' },
        { 'type': TYPE_UINT32, 'name': 'ruleAction' },
        { 'block': BLOCK_STRING, 'name': 'netbios' },
        { 'type': TYPE_UINT32, 'name': 'urlCategory' },
        { 'type': TYPE_UINT32, 'name': 'urlReputation' },
        { 'block': BLOCK_STRING, 'name': 'url' },
        { 'type': TYPE_UINT32, 'name': 'clientId' },
        { 'block': BLOCK_STRING, 'name': 'clientVersion' },
        { 'type': TYPE_UUID, 'name': 'accessControlPolicyRevision' },
        { 'type': TYPE_UINT32, 'name': 'accessControlRuleId' },
        { 'type': TYPE_UUID, 'name': 'ingressIntefaceUuid' },
        { 'type': TYPE_UUID, 'name': 'egressIntefaceUuid' },
        { 'type': TYPE_UUID, 'name': 'ingressZoneUuid' },
        { 'type': TYPE_UUID, 'name': 'egressZoneUuid' },
        { 'type': TYPE_IPV6, 'name': 'sourceIpv6Address' },
        { 'type': TYPE_IPV6, 'name': 'destinationIpv6Address' },
        { 'type': TYPE_UINT16, 'name': 'sourceCountry' },
        { 'type': TYPE_UINT16, 'name': 'destinationCountry' },
        { 'type': TYPE_UUID, 'name': 'securityIntelligenceUuid' },
        { 'type': TYPE_UINT128, 'name': 'securityContext' },
        { 'type': TYPE_UINT128, 'name': 'sslPolicyId' },
        { 'type': TYPE_UINT32, 'name': 'sslRuleId' },
        { 'type': TYPE_UINT32, 'name': 'sslActualAction' },
        { 'type': TYPE_UINT32, 'name': 'sslFlowStatus' },
        { 'type': TYPE_UINT160, 'name': 'sslCertificateFingerprint'}],

    # 159
    BLOCK_USER_LOGIN_INFORMATION_60: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'timestamp' },
        { 'type': TYPE_IPV4, 'name': 'ipv4Address' },
        { 'block': BLOCK_STRING, 'name': 'username' },
        { 'block': BLOCK_STRING, 'name': 'domain' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'realmId' },
        { 'type': TYPE_UINT32, 'name': 'endpointProfileId' },
        { 'type': TYPE_UINT32, 'name': 'securityGroupId' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'type': TYPE_UINT32, 'name': 'protocol' },
        { 'block': BLOCK_STRING, 'name': 'email' },
        { 'type': TYPE_IPV6, 'name': 'ipv6Address' },
        { 'type': TYPE_IPV6, 'name': 'locationIpv6Address' },
        { 'type': TYPE_BYTE, 'name': 'loginType' },
        { 'type': TYPE_BYTE, 'name': 'authType' },
        { 'block': BLOCK_STRING, 'name': 'reportedBy' }],

    # 160
    BLOCK_CONNECTION_STATISTICS_60: [
        # Documentation wrong. Missing @pad below
        # and ruleReason incorrectly specified as int16
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UUID, 'name': 'ingressZone' },
        { 'type': TYPE_UUID, 'name': 'egressZone' },
        { 'type': TYPE_UUID, 'name': 'ingressInterface' },
        { 'type': TYPE_UUID, 'name': 'egressInterface' },
        { 'type': TYPE_IPV6, 'name': 'initiatorIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'responderIpAddress' },
        { 'type': TYPE_UUID, 'name': 'policyRevision' },
        { 'type': TYPE_UINT32, 'name': 'ruleId' },
        { 'type': TYPE_UINT16, 'name': 'ruleAction' },
        { 'type': TYPE_UINT32, 'name': 'ruleReason' },
        { 'type': TYPE_UINT16, 'name': 'initiatorPort' },
        { 'type': TYPE_UINT16, 'name': 'responderPort' },
        { 'type': TYPE_UINT16, 'name': 'tcpFlag' },
        { 'type': TYPE_BYTE, 'name': 'protocol' },
        { 'type': TYPE_UUID, 'name': 'netflowSource' },
        { 'type': TYPE_UINT16, 'name': 'instanceId' },
        { 'type': TYPE_UINT16, 'name': 'connectionCounter' },
        { 'type': TYPE_UINT32, 'name': 'firstPacketTimestamp' },
        { 'type': TYPE_UINT32, 'name': 'lastPacketTimestamp' },
        { 'type': TYPE_UINT64, 'name': 'initiatorTransmittedPackets' },
        { 'type': TYPE_UINT64, 'name': 'responderTransmittedPackets' },
        { 'type': TYPE_UINT64, 'name': 'initiatorTransmittedBytes' },
        { 'type': TYPE_UINT64, 'name': 'responderTransmittedBytes' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' }, #applicationProtocolId
        { 'type': TYPE_UINT32, 'name': 'urlCategory' },
        { 'type': TYPE_UINT32, 'name': 'urlReputation' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'webApplicationId' },
        { 'block': BLOCK_STRING, 'name': 'clientUrl' },
        { 'block': BLOCK_STRING, 'name': 'netbios' },
        { 'block': BLOCK_STRING, 'name': 'clientApplicationVersion' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule1' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule2' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule3' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule4' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule5' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule6' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule7' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule8' },
        { 'type': TYPE_BYTE, 'name': 'securityIntelligenceSourceDestination' },
        { 'type': TYPE_BYTE, 'name': 'securityIntelligenceLayer' },
        { 'type': TYPE_UINT16, 'name': 'fileEventCount' },
        { 'type': TYPE_UINT16, 'name': 'intrusionEventCount' },
        { 'type': TYPE_UINT16, 'name': 'initiatorCountry' },
        { 'type': TYPE_UINT16, 'name': 'responderCountry' },
        { 'type': TYPE_UINT16, 'name': 'iocNumber' },
        { 'type': TYPE_UINT32, 'name': 'sourceAutonomousSystem' },
        { 'type': TYPE_UINT32, 'name': 'destinationAutonomousSystem' },
        { 'type': TYPE_UINT16, 'name': 'snmpIn' },
        { 'type': TYPE_UINT16, 'name': 'snmpOut' },
        { 'type': TYPE_BYTE, 'name': 'sourceTos' },
        { 'type': TYPE_BYTE, 'name': 'destinationTos' },
        { 'type': TYPE_BYTE, 'name': 'sourceMask' },
        { 'type': TYPE_BYTE, 'name': 'destinationMask' },
        { 'type': TYPE_UINT128, 'name': 'securityContext' },
        { 'type': TYPE_UINT16, 'name': 'vlanId' },
        { 'block': BLOCK_STRING, 'name': 'referencedHost' },
        { 'block': BLOCK_STRING, 'name': 'userAgent' },
        { 'block': BLOCK_STRING, 'name': 'httpReferrer' },
        { 'type': TYPE_UINT160, 'name': 'sslCertificateFingerprint' },
        { 'type': TYPE_UINT128, 'name': 'sslPolicyId' },
        { 'type': TYPE_UINT32, 'name': 'sslRuleId' },
        { 'type': TYPE_UINT16, 'name': 'sslCipherSuite' },
        { 'type': TYPE_BYTE, 'name': 'sslVersion' },
        { 'type': TYPE_UINT32, 'name': 'sslServerCertificateStatus' },
        { 'type': TYPE_UINT16, 'name': 'sslActualAction' },
        { 'type': TYPE_UINT16, 'name': 'sslExpectedAction' },
        { 'type': TYPE_UINT16, 'name': 'sslFlowStatus' },
        { 'type': TYPE_UINT32, 'name': 'sslFlowError' },
        { 'type': TYPE_UINT32, 'name': 'sslFlowMessages' },
        { 'type': TYPE_UINT64, 'name': 'sslFlowFlags' },
        { 'block': BLOCK_STRING, 'name': 'sslServerName' },
        { 'type': TYPE_UINT32, 'name': 'sslUrlCategory' },
        { 'type': TYPE_UINT256, 'name': 'sslSessionId' },
        { 'type': TYPE_BYTE, 'name': 'sslSessionIdLength' },
        { 'type': TYPE_UINT160, 'name': 'sslTicketId' },
        { 'type': TYPE_BYTE, 'name': 'sslTicketIdLength' },
        { 'type': TYPE_UUID, 'name': 'networkAnalysisPolicyRevision' },
        { 'type': TYPE_UINT32, 'name': 'endpointProfileId' },
        { 'type': TYPE_UINT32, 'name': 'securityGroupId' },
        { 'type': TYPE_IPV6, 'name': 'locationIpv6' },
        { 'type': TYPE_UINT32, 'name': 'httpResponse' },
        { 'block': BLOCK_STRING, 'name': 'dnsQuery' },
        { 'type': TYPE_UINT16, 'name': 'dnsRecordType' },
        { 'type': TYPE_UINT16, 'name': 'dnsResponseType' },
        { 'type': TYPE_UINT32, 'name': 'dnsTtl' },
        { 'type': TYPE_UUID, 'name': 'sinkholeUuid' },
        { 'type': TYPE_UINT32, 'name': 'securityIntelligenceList1' },
        { 'type': TYPE_UINT32, 'name': 'securityIntelligenceList2'}],

    # 163
    BLOCK_CONNECTION_STATISTICS_61: [
        # Documentation wrong. Missing @pad below
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UUID, 'name': 'ingressZone' },
        { 'type': TYPE_UUID, 'name': 'egressZone' },
        { 'type': TYPE_UUID, 'name': 'ingressInterface' },
        { 'type': TYPE_UUID, 'name': 'egressInterface' },
        { 'type': TYPE_IPV6, 'name': 'initiatorIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'responderIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'originalClientIpAddress' },
        { 'type': TYPE_UUID, 'name': 'policyRevision' },
        { 'type': TYPE_UINT32, 'name': 'ruleId' },
        { 'type': TYPE_UINT32, 'name': 'tunnelRuleId' },
        { 'type': TYPE_UINT16, 'name': 'ruleAction' },
        { 'type': TYPE_UINT32, 'name': 'ruleReason' },
        { 'type': TYPE_UINT16, 'name': 'initiatorPort' },
        { 'type': TYPE_UINT16, 'name': 'responderPort' },
        { 'type': TYPE_UINT16, 'name': 'tcpFlag' },
        { 'type': TYPE_BYTE, 'name': 'protocol' },
        { 'type': TYPE_UUID, 'name': 'netflowSource' },
        { 'type': TYPE_UINT16, 'name': 'instanceId' },
        { 'type': TYPE_UINT16, 'name': 'connectionCounter' },
        { 'type': TYPE_UINT32, 'name': 'firstPacketTimestamp' },
        { 'type': TYPE_UINT32, 'name': 'lastPacketTimestamp' },
        { 'type': TYPE_UINT64, 'name': 'initiatorTransmittedPackets' },
        { 'type': TYPE_UINT64, 'name': 'responderTransmittedPackets' },
        { 'type': TYPE_UINT64, 'name': 'initiatorTransmittedBytes' },
        { 'type': TYPE_UINT64, 'name': 'responderTransmittedBytes' },
        { 'type': TYPE_UINT64, 'name': 'initiatorPacketsDropped' },
        { 'type': TYPE_UINT64, 'name': 'responderPacketsDropped' },
        { 'type': TYPE_UINT64, 'name': 'initiatorBytesDropped' },
        { 'type': TYPE_UINT64, 'name': 'responderBytesDropped' },
        { 'type': TYPE_UUID, 'name': 'qosAppliedInterface' },
        { 'type': TYPE_UINT32, 'name': 'qosRuleId' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' }, #applicationProtocolId
        { 'type': TYPE_UINT32, 'name': 'urlCategory' },
        { 'type': TYPE_UINT32, 'name': 'urlReputation' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'webApplicationId' },
        { 'block': BLOCK_STRING, 'name': 'clientUrl' },
        { 'block': BLOCK_STRING, 'name': 'netbios' },
        { 'block': BLOCK_STRING, 'name': 'clientApplicationVersion' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule1' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule2' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule3' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule4' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule5' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule6' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule7' },
        { 'type': TYPE_UINT32, 'name': 'monitorRule8' },
        { 'type': TYPE_BYTE, 'name': 'securityIntelligenceSourceDestination' },
        { 'type': TYPE_BYTE, 'name': 'securityIntelligenceLayer' },
        { 'type': TYPE_UINT16, 'name': 'fileEventCount' },
        { 'type': TYPE_UINT16, 'name': 'intrusionEventCount' },
        { 'type': TYPE_UINT16, 'name': 'initiatorCountry' },
        { 'type': TYPE_UINT16, 'name': 'responderCountry' },
        { 'type': TYPE_UINT16, 'name': 'originalClientCountry' },
        { 'type': TYPE_UINT16, 'name': 'iocNumber' },
        { 'type': TYPE_UINT32, 'name': 'sourceAutonomousSystem' },
        { 'type': TYPE_UINT32, 'name': 'destinationAutonomousSystem' },
        { 'type': TYPE_UINT16, 'name': 'snmpIn' },
        { 'type': TYPE_UINT16, 'name': 'snmpOut' },
        { 'type': TYPE_BYTE, 'name': 'sourceTos' },
        { 'type': TYPE_BYTE, 'name': 'destinationTos' },
        { 'type': TYPE_BYTE, 'name': 'sourceMask' },
        { 'type': TYPE_BYTE, 'name': 'destinationMask' },
        { 'type': TYPE_UUID, 'name': 'securityContext' },
        { 'type': TYPE_UINT16, 'name': 'vlanId' },
        { 'block': BLOCK_STRING, 'name': 'referencedHost' },
        { 'block': BLOCK_STRING, 'name': 'userAgent' },
        { 'block': BLOCK_STRING, 'name': 'httpReferrer' },
        { 'type': TYPE_UINT160, 'name': 'sslCertificateFingerprint' },
        { 'type': TYPE_UUID, 'name': 'sslPolicyId' },
        { 'type': TYPE_UINT32, 'name': 'sslRuleId' },
        { 'type': TYPE_UINT16, 'name': 'sslCipherSuite' },
        { 'type': TYPE_BYTE, 'name': 'sslVersion' },
        # sslServerCertificateStatus: Incorrect documentation
        { 'type': TYPE_UINT32, 'name': 'sslServerCertificateStatus' },
        { 'type': TYPE_UINT16, 'name': 'sslActualAction' },
        { 'type': TYPE_UINT16, 'name': 'sslExpectedAction' },
        { 'type': TYPE_UINT16, 'name': 'sslFlowStatus' },
        { 'type': TYPE_UINT32, 'name': 'sslFlowError' },
        { 'type': TYPE_UINT32, 'name': 'sslFlowMessages' },
        { 'type': TYPE_UINT64, 'name': 'sslFlowFlags' },
        { 'block': BLOCK_STRING, 'name': 'sslServerName' },
        { 'type': TYPE_UINT32, 'name': 'sslUrlCategory' },
        { 'type': TYPE_UINT256, 'name': 'sslSessionId' },
        { 'type': TYPE_BYTE, 'name': 'sslSessionIdLength' },
        { 'type': TYPE_UINT160, 'name': 'sslTicketId' },
        { 'type': TYPE_BYTE, 'name': 'sslTicketIdLength' },
        { 'type': TYPE_UUID, 'name': 'networkAnalysisPolicyRevision' },
        { 'type': TYPE_UINT32, 'name': 'endpointProfileId' },
        { 'type': TYPE_UINT32, 'name': 'securityGroupId' },
        { 'type': TYPE_IPV6, 'name': 'locationIpv6' },
        { 'type': TYPE_UINT32, 'name': 'httpResponse' },
        { 'block': BLOCK_STRING, 'name': 'dnsQuery' },
        { 'type': TYPE_UINT16, 'name': 'dnsRecordType' },
        { 'type': TYPE_UINT16, 'name': 'dnsResponseType' },
        { 'type': TYPE_UINT32, 'name': 'dnsTtl' },
        { 'type': TYPE_UUID, 'name': 'sinkholeUuid' },
        { 'type': TYPE_UINT32, 'name': 'securityIntelligenceList1' },
        { 'type': TYPE_UINT32, 'name': 'securityIntelligenceList2'}],

    # 165
    BLOCK_USER_LOGIN_INFORMATION_61: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'timestamp' },
        { 'type': TYPE_IPV4, 'name': 'ipv4Address' },
        { 'block': BLOCK_STRING, 'name': 'username' },
        { 'block': BLOCK_STRING, 'name': 'domain' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'realmId' },
        { 'type': TYPE_UINT32, 'name': 'endpointProfileId' },
        { 'type': TYPE_UINT32, 'name': 'securityGroupId' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'type': TYPE_UINT32, 'name': 'protocol' },
        { 'type': TYPE_UINT16, 'name': 'port' },
        { 'type': TYPE_UINT16, 'name': 'rangeStart' },
        { 'type': TYPE_UINT16, 'name': 'startPort' },
        { 'type': TYPE_UINT16, 'name': 'endPort' },
        { 'block': BLOCK_STRING, 'name': 'email' },
        { 'type': TYPE_IPV6, 'name': 'ipv6Address' },
        { 'type': TYPE_IPV6, 'name': 'locationIpv6Address' },
        { 'type': TYPE_BYTE, 'name': 'loginType' },
        { 'type': TYPE_BYTE, 'name': 'authType' },
        { 'block': BLOCK_STRING, 'name': 'reportedBy' }],

    # 10000
    # This is not strictly a block (there's no type or length) - and it's not
    # documented as such, however, it is a very commonly repeating structure
    # and this makes for less repeated code.
    BLOCK_METADATA_ID_LENGTH_NAME: [
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'type': TYPE_UINT32, 'name': 'length' },
        { 'type': TYPE_VARIABLE, 'length': 'length', 'name': 'name'}]
}
