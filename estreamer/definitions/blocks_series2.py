
#********************************************************************
#      File:    blocks_series2.py
#      Author:  Sam Strachan
#
#      Description:
#       Series 2 blocks
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

from estreamer.definitions.blocks_series1 import BLOCK_STRING
from estreamer.definitions.blocks_series1 import BLOCK_BLOB
from estreamer.definitions.core import TYPE_BYTE
from estreamer.definitions.core import TYPE_UINT16
from estreamer.definitions.core import TYPE_UINT32
from estreamer.definitions.core import TYPE_UINT64
from estreamer.definitions.core import TYPE_UINT128
from estreamer.definitions.core import TYPE_UINT160
from estreamer.definitions.core import TYPE_UINT256
from estreamer.definitions.core import TYPE_UUID
from estreamer.definitions.core import TYPE_IPV6

# Without this the series 1 and 2 types collide. There is probably
# another nicer way to do this but right now this will have to do
BLOCK_SERIES_2_SHIM = 0x00010000

# Series 2 data blocks
BLOCK_EVENT_EXTRA_DATA                      = 4 | BLOCK_SERIES_2_SHIM
BLOCK_EVENT_EXTRA_DATA_METADATA             = 5 | BLOCK_SERIES_2_SHIM
BLOCK_UUID_STRING                           = 14 | BLOCK_SERIES_2_SHIM
BLOCK_ACCESS_CONTROL_RULE                   = 15 | BLOCK_SERIES_2_SHIM
BLOCK_ICMP_TYPE_DATA                        = 19 | BLOCK_SERIES_2_SHIM
BLOCK_ICMP_CODE_DATA                        = 20 | BLOCK_SERIES_2_SHIM
BLOCK_IP_REPUTATION_CATEGORY                = 22 | BLOCK_SERIES_2_SHIM
BLOCK_RULE_DOCUMENTATION_DATA_52            = 27 | BLOCK_SERIES_2_SHIM
BLOCK_GEOLOCATION_52                        = 28 | BLOCK_SERIES_2_SHIM
BLOCK_IOC_NAME_53                           = 39 | BLOCK_SERIES_2_SHIM
BLOCK_FILE_EVENT_SHA_HASH_53                = 40 | BLOCK_SERIES_2_SHIM
BLOCK_INTRUSION_EVENT_53                    = 41 | BLOCK_SERIES_2_SHIM
BLOCK_SSL_CERTIFICATION_DETAILS_54          = 50 | BLOCK_SERIES_2_SHIM
BLOCK_FILE_EVENT_60                         = 56 | BLOCK_SERIES_2_SHIM
BLOCK_USER_60                               = 57 | BLOCK_SERIES_2_SHIM
BLOCK_ENDPOINT_PROFILE_60                   = 58 | BLOCK_SERIES_2_SHIM
BLOCK_ACCESS_CONTROL_POLICY_RULE_REASON_60  = 59 | BLOCK_SERIES_2_SHIM
BLOCK_INTRUSION_EVENT_60                    = 60 | BLOCK_SERIES_2_SHIM
BLOCK_ID_NAME_DESCRIPTION                   = 61 | BLOCK_SERIES_2_SHIM
BLOCK_MALWARE_EVENT_60                      = 62 | BLOCK_SERIES_2_SHIM
BLOCK_ACCESS_CONTROL_POLICY_METADATA        = 64 | BLOCK_SERIES_2_SHIM

BLOCKS_SERIES_2 = {
    # 4 Series 2
    BLOCK_EVENT_EXTRA_DATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UINT32, 'name': 'eventId' },
        { 'type': TYPE_UINT32, 'name': 'eventSecond' },
        { 'type': TYPE_UINT32, 'name': 'type' },
        { 'block': BLOCK_BLOB, 'name': 'blob' }],

    # 5
    BLOCK_EVENT_EXTRA_DATA_METADATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'type' },
        { 'block': BLOCK_STRING, 'name': 'name' },
        { 'block': BLOCK_STRING, 'name': 'encoding' }],

    # 14
    BLOCK_UUID_STRING: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UUID, 'name': 'uuid' },
        { 'block': BLOCK_STRING, 'name': 'name' }],

    # 15
    BLOCK_ACCESS_CONTROL_RULE: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UUID, 'name': 'uuid' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'block': BLOCK_STRING, 'name': 'name' }],

    # 19
    BLOCK_ICMP_TYPE_DATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'type' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'block': BLOCK_STRING, 'name': 'description' }],

    # 20
    BLOCK_ICMP_CODE_DATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'code' },
        { 'type': TYPE_UINT16, 'name': 'type' },
        { 'type': TYPE_UINT16, 'name': 'protocol' },
        { 'block': BLOCK_STRING, 'name': 'description' }],

    # 22
    BLOCK_IP_REPUTATION_CATEGORY: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'type': TYPE_UUID, 'name': 'accessControlPolicyUuid' },
        { 'block': BLOCK_STRING, 'name': 'name' }],

    # 27
    BLOCK_RULE_DOCUMENTATION_DATA_52: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'signatureId' },
        { 'type': TYPE_UINT32, 'name': 'generatorId' },
        { 'type': TYPE_UINT32, 'name': 'revision' },
        { 'block': BLOCK_STRING, 'name': 'summary' },
        { 'block': BLOCK_STRING, 'name': 'impact' },
        { 'block': BLOCK_STRING, 'name': 'detail' },
        { 'block': BLOCK_STRING, 'name': 'affectedSystems' },
        { 'block': BLOCK_STRING, 'name': 'attackScenarios' },
        { 'block': BLOCK_STRING, 'name': 'easeOfAttack' },
        { 'block': BLOCK_STRING, 'name': 'falsePositives' },
        { 'block': BLOCK_STRING, 'name': 'falseNegatives' },
        { 'block': BLOCK_STRING, 'name': 'correctiveAction' },
        { 'block': BLOCK_STRING, 'name': 'contributors' },
        { 'block': BLOCK_STRING, 'name': 'additionalReferences' } ],

    # 28
    BLOCK_GEOLOCATION_52: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT16, 'name': 'countryCode' },
        { 'block': BLOCK_STRING, 'name': 'country' }],

    # 39
    BLOCK_IOC_NAME_53: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'block': BLOCK_STRING, 'name': 'category' },
        { 'block': BLOCK_STRING, 'name': 'eventType' }],

    # 40
    BLOCK_FILE_EVENT_SHA_HASH_53: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT256, 'name': 'shaHash' },
        { 'block': BLOCK_STRING, 'name': 'fileName' },
        { 'type': TYPE_BYTE, 'name': 'disposition' },
        { 'type': TYPE_BYTE, 'name': 'userDefined'}],

    # 41 - LEGACY
    BLOCK_INTRUSION_EVENT_53: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UINT32, 'name': 'eventId' },
        { 'type': TYPE_UINT32, 'name': 'eventSecond' },
        { 'type': TYPE_UINT32, 'name': 'eventMicrosecond' },
        { 'type': TYPE_UINT32, 'name': 'ruleId' },
        { 'type': TYPE_UINT32, 'name': 'generatorId' },
        { 'type': TYPE_UINT32, 'name': 'ruleRevision' },
        { 'type': TYPE_UINT32, 'name': 'classificationId' },
        { 'type': TYPE_UINT32, 'name': 'priorityId' },
        { 'type': TYPE_IPV6, 'name': 'sourceIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'destinationIpAddress' },
        { 'type': TYPE_UINT16, 'name': 'sourcePortOrIcmpType' },
        { 'type': TYPE_UINT16, 'name': 'destinationPortOrIcmpType' },
        { 'type': TYPE_BYTE, 'name': 'ipProtocolId' },
        { 'type': TYPE_BYTE, 'name': 'impactFlags' },
        { 'type': TYPE_BYTE, 'name': 'impact' },
        { 'type': TYPE_BYTE, 'name': 'blocked' },
        { 'type': TYPE_UINT32, 'name': 'mplsLabel' },
        { 'type': TYPE_UINT16, 'name': 'vlanId' },
        { 'type': TYPE_UINT16, 'name': 'pad' },
        { 'type': TYPE_UUID, 'name': 'policyUuid' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'webApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'type': TYPE_UINT32, 'name': 'accessControlRuleId' },
        { 'type': TYPE_UUID, 'name': 'accessControlPolicyUuid' },
        { 'type': TYPE_UUID, 'name': 'interfaceIngressUuid' },
        { 'type': TYPE_UUID, 'name': 'interfaceEgressUuid' },
        { 'type': TYPE_UUID, 'name': 'securityZoneIngressUuid' },
        { 'type': TYPE_UUID, 'name': 'securityZoneEgressUuid' },
        { 'type': TYPE_UINT32, 'name': 'connectionTimestamp' },
        { 'type': TYPE_UINT16, 'name': 'connectionInstanceId' },
        { 'type': TYPE_UINT16, 'name': 'connectionCounter' },
        { 'type': TYPE_UINT16, 'name': 'sourceCountry' },
        { 'type': TYPE_UINT16, 'name': 'destinationCountry' },
        { 'type': TYPE_UINT16, 'name': 'iocNumber' }],

    # 50
    BLOCK_SSL_CERTIFICATION_DETAILS_54: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT160, 'name': 'fingerprintShaHash' },
        { 'type': TYPE_UINT160, 'name': 'publicKeyShaHash' },
        { 'type': TYPE_UINT160, 'name': 'serialNumber' },
        { 'type': TYPE_UINT32, 'name': 'serialNumberLength' },
        { 'block': BLOCK_STRING, 'name': 'subjectCn' },
        { 'block': BLOCK_STRING, 'name': 'subjectOrganisation' },
        { 'block': BLOCK_STRING, 'name': 'subjectOU' },
        { 'block': BLOCK_STRING, 'name': 'subjectCountry' },
        { 'block': BLOCK_STRING, 'name': 'issuerCn' },
        { 'block': BLOCK_STRING, 'name': 'issuerOrganisation' },
        { 'block': BLOCK_STRING, 'name': 'issuerOU' },
        { 'block': BLOCK_STRING, 'name': 'issuerCountry' },
        { 'type': TYPE_UINT32, 'name': 'validStartDate' },
        { 'type': TYPE_UINT32, 'name': 'validFinishDate' } ],

    # 56
    BLOCK_FILE_EVENT_60: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UINT16, 'name': 'connectionInstance' },
        { 'type': TYPE_UINT16, 'name': 'connectionCounter' },
        { 'type': TYPE_UINT32, 'name': 'connectionTimestamp' },
        { 'type': TYPE_UINT32, 'name': 'fileEventTimestamp' },
        { 'type': TYPE_IPV6, 'name': 'sourceIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'destinationIpAddress' },
        { 'type': TYPE_BYTE, 'name': 'disposition' },
        { 'type': TYPE_BYTE, 'name': 'speroDisposition' },
        { 'type': TYPE_BYTE, 'name': 'fileStorageStatus' },
        { 'type': TYPE_BYTE, 'name': 'fileAnalysisStatus' },
        { 'type': TYPE_BYTE, 'name': 'localMalwareAnalysisStatus' },
        { 'type': TYPE_BYTE, 'name': 'archiveFileStatus' },
        { 'type': TYPE_BYTE, 'name': 'threatScore' },
        { 'type': TYPE_BYTE, 'name': 'action' },
        { 'type': TYPE_UINT256, 'name': 'shaHash' },
        { 'type': TYPE_UINT32, 'name': 'fileTypeId' },
        { 'block': BLOCK_STRING, 'name': 'fileName' },
        { 'type': TYPE_UINT64, 'name': 'fileSize' },
        { 'type': TYPE_BYTE, 'name': 'direction' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'block': BLOCK_STRING, 'name': 'uri' },
        { 'block': BLOCK_STRING, 'name': 'signature' },
        { 'type': TYPE_UINT16, 'name': 'sourcePort' },
        { 'type': TYPE_UINT16, 'name': 'destinationPort' },
        { 'type': TYPE_BYTE, 'name': 'protocol' },
        { 'type': TYPE_UUID, 'name': 'accessControlPolicyUuid' },
        { 'type': TYPE_UINT16, 'name': 'sourceCountry' },
        { 'type': TYPE_UINT16, 'name': 'destinationCountry' },
        { 'type': TYPE_UINT32, 'name': 'webApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'type': TYPE_UINT128, 'name': 'securityContext' },
        { 'type': TYPE_UINT160, 'name': 'sslCertificateFingerprint' },
        { 'type': TYPE_UINT16, 'name': 'sslActualAction' },
        { 'type': TYPE_UINT16, 'name': 'sslFlowStatus' },
        { 'block': BLOCK_STRING, 'name': 'archiveSha' },
        { 'block': BLOCK_STRING, 'name': 'archiveName' },
        { 'type': TYPE_BYTE, 'name': 'archiveDepth'},
        { 'type': TYPE_UINT32, 'name': 'httpResponse'}],

    # 57
    BLOCK_USER_60: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'type': TYPE_UINT32, 'name': 'protocol' },
        { 'block': BLOCK_STRING, 'name': 'name' }],

    # 58
    BLOCK_ENDPOINT_PROFILE_60: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'block': BLOCK_STRING, 'name': 'profileName' },
        { 'block': BLOCK_STRING, 'name': 'fullName' }],

    # 59
    BLOCK_ACCESS_CONTROL_POLICY_RULE_REASON_60: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'id' },
        { 'block': BLOCK_STRING, 'name': 'description' }],

    # 60
    BLOCK_INTRUSION_EVENT_60: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UINT32, 'name': 'eventId' },
        { 'type': TYPE_UINT32, 'name': 'eventSecond' },
        { 'type': TYPE_UINT32, 'name': 'eventMicrosecond' },
        { 'type': TYPE_UINT32, 'name': 'ruleId' },
        { 'type': TYPE_UINT32, 'name': 'generatorId' },
        { 'type': TYPE_UINT32, 'name': 'ruleRevision' },
        { 'type': TYPE_UINT32, 'name': 'classificationId' },
        { 'type': TYPE_UINT32, 'name': 'priorityId' },
        { 'type': TYPE_IPV6, 'name': 'sourceIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'destinationIpAddress' },
        { 'type': TYPE_UINT16, 'name': 'sourcePortOrIcmpType' },
        { 'type': TYPE_UINT16, 'name': 'destinationPortOrIcmpType' },
        { 'type': TYPE_BYTE, 'name': 'ipProtocolId' },
        { 'type': TYPE_BYTE, 'name': 'impactFlags' },
        { 'type': TYPE_BYTE, 'name': 'impact' },
        { 'type': TYPE_BYTE, 'name': 'blocked' },
        { 'type': TYPE_UINT32, 'name': 'mplsLabel' },
        { 'type': TYPE_UINT16, 'name': 'vlanId' },
        { 'type': TYPE_UINT16, 'name': 'pad' },
        { 'type': TYPE_UUID, 'name': 'policyUuid' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UINT32, 'name': 'webApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'type': TYPE_UINT32, 'name': 'accessControlRuleId' },
        { 'type': TYPE_UUID, 'name': 'accessControlPolicyUuid' },
        { 'type': TYPE_UUID, 'name': 'interfaceIngressUuid' },
        { 'type': TYPE_UUID, 'name': 'interfaceEgressUuid' },
        { 'type': TYPE_UUID, 'name': 'securityZoneIngressUuid' },
        { 'type': TYPE_UUID, 'name': 'securityZoneEgressUuid' },
        { 'type': TYPE_UINT32, 'name': 'connectionTimestamp' },
        { 'type': TYPE_UINT16, 'name': 'connectionInstanceId' },
        { 'type': TYPE_UINT16, 'name': 'connectionCounter' },
        { 'type': TYPE_UINT16, 'name': 'sourceCountry' },
        { 'type': TYPE_UINT16, 'name': 'destinationCountry' },
        { 'type': TYPE_UINT16, 'name': 'iocNumber' },
        { 'type': TYPE_UINT128, 'name': 'securityContext' },
        { 'type': TYPE_UINT160, 'name': 'sslCertificateFingerprint' },
        { 'type': TYPE_UINT16, 'name': 'sslActualAction' },
        { 'type': TYPE_UINT16, 'name': 'sslFlowStatus' },
        { 'type': TYPE_UUID, 'name': 'networkAnalysisPolicyUuid' },
        { 'type': TYPE_UINT32, 'name': 'httpResponse'}],

    # 61
    BLOCK_ID_NAME_DESCRIPTION: [
        { 'type': TYPE_UINT32, 'name': 'blockType'},
        { 'type': TYPE_UINT32, 'name': 'blockLength'},
        { 'type': TYPE_UINT32, 'name': 'id'},
        { 'block': BLOCK_STRING, 'name': 'name' },
        { 'block': BLOCK_STRING, 'name': 'description' }],

    # 62
    BLOCK_MALWARE_EVENT_60: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UUID, 'name': 'agentUuid' },
        { 'type': TYPE_UUID, 'name': 'cloudUuid' },
        { 'type': TYPE_UINT32, 'name': 'malwareEventTimestamp' },
        { 'type': TYPE_UINT32, 'name': 'eventTypeId' },
        { 'type': TYPE_UINT32, 'name': 'eventSubtypeId' },
        { 'type': TYPE_BYTE, 'name': 'detectorId' },
        { 'block': BLOCK_STRING, 'name': 'detectionName' },
        { 'block': BLOCK_STRING, 'name': 'user' },
        { 'block': BLOCK_STRING, 'name': 'fileName' },
        { 'block': BLOCK_STRING, 'name': 'filePath' },
        { 'block': BLOCK_STRING, 'name': 'fileShaHash' },
        { 'type': TYPE_UINT32, 'name': 'fileSize' },
        { 'type': TYPE_UINT32, 'name': 'fileType' },
        { 'type': TYPE_UINT32, 'name': 'fileTimestamp' },
        { 'block': BLOCK_STRING, 'name': 'parentFileName' },
        { 'block': BLOCK_STRING, 'name': 'parentShaHash' },
        { 'block': BLOCK_STRING, 'name': 'eventDescription' },
        { 'type': TYPE_UINT32, 'name': 'deviceId' },
        { 'type': TYPE_UINT16, 'name': 'connectionInstance' },
        { 'type': TYPE_UINT16, 'name': 'connectionCounter' },
        { 'type': TYPE_UINT32, 'name': 'connectionEventTimestamp' },
        { 'type': TYPE_BYTE, 'name': 'direction' },
        { 'type': TYPE_IPV6, 'name': 'sourceIpAddress' },
        { 'type': TYPE_IPV6, 'name': 'destinationIpAddress' },
        { 'type': TYPE_UINT32, 'name': 'applicationId' },
        { 'type': TYPE_UINT32, 'name': 'userId' },
        { 'type': TYPE_UUID, 'name': 'accessControlPolicyUuid' },
        { 'type': TYPE_BYTE, 'name': 'disposition' },
        { 'type': TYPE_BYTE, 'name': 'retroDisposition' },
        { 'block': BLOCK_STRING, 'name': 'uri' },
        { 'type': TYPE_UINT16, 'name': 'sourcePort' },
        { 'type': TYPE_UINT16, 'name': 'destinationPort' },
        { 'type': TYPE_UINT16, 'name': 'sourceCountry' },
        { 'type': TYPE_UINT16, 'name': 'destinationCountry' },
        { 'type': TYPE_UINT32, 'name': 'webApplicationId' },
        { 'type': TYPE_UINT32, 'name': 'clientApplicationId' },
        { 'type': TYPE_BYTE, 'name': 'action' },
        { 'type': TYPE_BYTE, 'name': 'protocol' },
        { 'type': TYPE_BYTE, 'name': 'threatScore' },
        { 'type': TYPE_UINT16, 'name': 'iocNumber' },
        { 'type': TYPE_UINT128, 'name': 'securityContext' },
        { 'type': TYPE_UINT160, 'name': 'sslCertificateFingerprint' },
        { 'type': TYPE_UINT16, 'name': 'sslActualAction' },
        { 'type': TYPE_UINT16, 'name': 'sslFlowStatus' },
        { 'block': BLOCK_STRING, 'name': 'archiveSha' },
        { 'block': BLOCK_STRING, 'name': 'archiveName' },
        { 'type': TYPE_BYTE, 'name': 'archiveDepth' },
        { 'type': TYPE_UINT32, 'name': 'httpResponse'}],

    # 64
    BLOCK_ACCESS_CONTROL_POLICY_METADATA: [
        { 'type': TYPE_UINT32, 'name': 'blockType' },
        { 'type': TYPE_UINT32, 'name': 'blockLength' },
        { 'type': TYPE_UUID, 'name': 'uuid' },
        { 'type': TYPE_UINT32, 'name': 'sensorId' },
        { 'block': BLOCK_STRING, 'name': 'name' } ],
}
