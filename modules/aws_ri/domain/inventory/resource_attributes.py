"""Resource-specific attribute extraction helpers."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from typing import Callable, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from aws_ri.domain.inventory.resource import Resource

AttributeFn = Callable[[dict[str, Any], "Resource", datetime], Any]
MAX_DEFAULT_CONFIG_ATTRIBUTES = 10


def extract_resource_attributes(
    resource: Resource,
    reference_time: Optional[datetime] = None,
) -> "OrderedDict[str, str]":
    """Return ordered attribute dict for a resource."""
    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    extractor = _RESOURCE_EXTRACTORS.get(resource.resource_type)
    configuration: dict[str, Any] = resource.configuration or {}

    values: "OrderedDict[str, str]"
    if extractor:
        values = extractor(configuration, resource, reference_time)
    else:
        values = OrderedDict()

    remaining_slots = MAX_DEFAULT_CONFIG_ATTRIBUTES - len(values)
    if remaining_slots > 0:
        fallback = _default_configuration_attributes(configuration, set(values.keys()), remaining_slots)
        values.update(fallback)

    return values


def attribute_headers_for_type(resource_type: str) -> list[str]:
    """List attribute headers registered for a resource type."""
    return list(_RESOURCE_HEADERS.get(resource_type, []))


def _register(resource_type: str, definitions: list[tuple[str, AttributeFn]]) -> None:
    headers = [label for label, _ in definitions]

    def extractor(configuration: dict[str, Any], resource: Resource, ref_time: datetime) -> OrderedDict[str, str]:
        values: "OrderedDict[str, str]" = OrderedDict()
        for label, func in definitions:
            raw_value = func(configuration, resource, ref_time)
            formatted = _normalize_value(raw_value)
            if formatted is not None and formatted != "":
                values[label] = formatted
        return values

    _RESOURCE_EXTRACTORS[resource_type] = extractor
    _RESOURCE_HEADERS[resource_type] = headers


def _normalize_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, dict):
        entries = [
            f"{k}={v}" for k, v in value.items() if v not in (None, "")
        ]
        return ", ".join(entries) if entries else None
    if isinstance(value, (list, tuple, set)):
        entries = [str(v) for v in value if v not in (None, "")]
        return ", ".join(entries) if entries else None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _safe_get(data: Optional[dict[str, Any]], path: list[str]) -> Any:
    current: Any = data or {}
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


def _join(values: list[Any]) -> Optional[str]:
    entries = [str(v) for v in values if v not in (None, "", [])]
    return ", ".join(entries) if entries else None


def _parse_time(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _normalized_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_duration(start: Optional[datetime], end: datetime) -> Optional[str]:
    start = _normalized_datetime(start)
    end = _normalized_datetime(end)
    if not start or not end:
        return None
    delta = end - start
    total_seconds = int(delta.total_seconds())
    if total_seconds < 0:
        return None
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and len(parts) < 2:
        parts.append(f"{minutes}m")
    return " ".join(parts) if parts else "<1m"


def _security_groups_from(configuration: dict[str, Any]) -> list[str]:
    groups: list[str] = []
    for raw in configuration.get("securityGroups", []) or []:
        if isinstance(raw, dict):
            groups.append(raw.get("groupId") or raw.get("GroupId") or raw.get("groupName"))
        else:
            groups.append(str(raw))
    for iface in configuration.get("networkInterfaces", []) or []:
        for raw in iface.get("groups", []) or iface.get("groupSet", []) or []:
            if isinstance(raw, dict):
                groups.append(raw.get("groupId") or raw.get("GroupId") or raw.get("groupName"))
            else:
                groups.append(str(raw))
    return [g for g in groups if g]


def _awsvpc_subnets(configuration: dict[str, Any]) -> list[str]:
    return _safe_get(configuration, ["networkConfiguration", "awsvpcConfiguration", "subnets"]) or []


def _awsvpc_security_groups(configuration: dict[str, Any]) -> list[str]:
    return _safe_get(configuration, ["networkConfiguration", "awsvpcConfiguration", "securityGroups"]) or []


def _awsvpc_assign_public_ip(configuration: dict[str, Any]) -> Optional[str]:
    return _safe_get(configuration, ["networkConfiguration", "awsvpcConfiguration", "assignPublicIp"])


def _backup_rules(configuration: dict[str, Any]) -> list[dict[str, Any]]:
    rules = _safe_get(configuration, ["backupPlan", "rules"])
    return rules if isinstance(rules, list) else []


def _backup_rule_names(configuration: dict[str, Any]) -> list[str]:
    return [rule.get("ruleName") for rule in _backup_rules(configuration) if isinstance(rule, dict) and rule.get("ruleName")]


def _backup_rule_vaults(configuration: dict[str, Any]) -> list[str]:
    names = []
    for rule in _backup_rules(configuration):
        vault = rule.get("targetBackupVaultName") or rule.get("targetBackupVault")
        if vault:
            names.append(vault)
    return names


def _backup_advanced_settings(configuration: dict[str, Any]) -> list[str]:
    settings = []
    for entry in configuration.get("advancedBackupSettings", []) or []:
        resource_type = entry.get("resourceType")
        options = entry.get("backupOptions", {})
        if resource_type and options:
            option_parts = [f"{key}={value}" for key, value in options.items()]
            settings.append(f"{resource_type}: {'; '.join(option_parts)}")
    return settings


_RESOURCE_EXTRACTORS: dict[str, Callable[[dict[str, Any], "Resource", datetime], OrderedDict[str, str]]] = {}
_RESOURCE_HEADERS: dict[str, list[str]] = {}


def _default_configuration_attributes(
    configuration: Optional[dict[str, Any]],
    existing_labels: set[str],
    limit: int,
) -> "OrderedDict[str, str]":
    """Extract generic attributes from raw configuration to fill empty slots."""
    fallback: "OrderedDict[str, str]" = OrderedDict()
    if not configuration:
        return fallback

    for label, value in _flatten_configuration(configuration):
        if label in existing_labels:
            continue
        if value in (None, ""):
            continue
        fallback[label] = value
        if len(fallback) >= limit:
            break

    return fallback


def _flatten_configuration(
    data: Any,
    path: Optional[list[str]] = None,
):
    """Yield flattened label/value pairs from a nested configuration."""
    path = path or []

    if isinstance(data, dict):
        for key, value in data.items():
            yield from _flatten_configuration(value, path + [str(key)])
    elif isinstance(data, list):
        if not data:
            return

        simple_values = []
        complex_items = []
        for item in data:
            if isinstance(item, (dict, list)):
                complex_items.append(item)
            else:
                normalized = _normalize_value(item)
                if normalized:
                    simple_values.append(normalized)

        if simple_values:
            label = ".".join(path) if path else "value"
            yield (label, ", ".join(simple_values))

        for idx, item in enumerate(complex_items):
            yield from _flatten_configuration(item, path + [str(idx)])
    else:
        normalized = _normalize_value(data)
        if normalized is not None:
            label = ".".join(path) if path else "value"
            yield (label, normalized)


# === EC2 INSTANCE ===
_register(
    "AWS::EC2::Instance",
    [
        ("Instance Type", lambda c, r, _: c.get("instanceType")),
        ("State", lambda c, r, _: _safe_get(c, ["state", "name"])),
        ("Availability Zone", lambda c, r, _: _safe_get(c, ["placement", "availabilityZone"])),
        ("VPC", lambda c, r, _: c.get("vpcId")),
        ("Subnet", lambda c, r, _: c.get("subnetId")),
        ("Security Groups", lambda c, r, _: _security_groups_from(c)),
        ("IAM Role", lambda c, r, _: _safe_get(c, ["iamInstanceProfile", "arn"])),
        (
            "Network Interfaces",
            lambda c, r, _: [iface.get("networkInterfaceId") for iface in c.get("networkInterfaces", []) or []],
        ),
        (
            "Public IPs",
            lambda c, r, _: [
                iface.get("association", {}).get("publicIp") or iface.get("publicIpAddress")
                for iface in c.get("networkInterfaces", []) or []
            ],
        ),
        (
            "Private IPs",
            lambda c, r, _: [iface.get("privateIpAddress") for iface in c.get("networkInterfaces", []) or []],
        ),
        (
            "EBS Volumes",
            lambda c, r, _: [bdm.get("ebs", {}).get("volumeId") for bdm in c.get("blockDeviceMappings", []) or []],
        ),
        (
            "Launch Time",
            lambda c, r, _: _safe_get(c, ["launchTime"]) or (r.creation_time.isoformat() if r.creation_time else None),
        ),
        (
            "Uptime",
            lambda c, r, ref: _format_duration(_parse_time(_safe_get(c, ["launchTime"]) or r.creation_time), ref),
        ),
    ],
)

# === EBS VOLUME ===
_register(
    "AWS::EC2::Volume",
    [
        ("Volume Type", lambda c, r, _: c.get("volumeType")),
        ("Size (GiB)", lambda c, r, _: c.get("size")),
        ("State", lambda c, r, _: c.get("state")),
        (
            "Attached Instances",
            lambda c, r, _: [att.get("instanceId") for att in c.get("attachments", []) or []],
        ),
        ("IOPS", lambda c, r, _: c.get("iops")),
        ("Throughput", lambda c, r, _: c.get("throughput")),
        ("Encrypted", lambda c, r, _: c.get("encrypted")),
        ("Snapshot ID", lambda c, r, _: c.get("snapshotId")),
    ],
)

# === RDS INSTANCE ===
_register(
    "AWS::RDS::DBInstance",
    [
        ("Engine", lambda c, r, _: c.get("engine")),
        ("Engine Version", lambda c, r, _: c.get("engineVersion")),
        ("Instance Class", lambda c, r, _: c.get("dBInstanceClass")),
        ("Allocated Storage", lambda c, r, _: c.get("allocatedStorage")),
        ("Multi-AZ", lambda c, r, _: c.get("multiAZ")),
        ("Storage Encrypted", lambda c, r, _: c.get("storageEncrypted")),
        (
            "Security Groups",
            lambda c, r, _: [sg.get("vpcSecurityGroupId") for sg in c.get("vpcSecurityGroups", []) or []],
        ),
        (
            "Subnet Group",
            lambda c, r, _: _safe_get(c, ["dBSubnetGroup", "dBSubnetGroupName"]),
        ),
        ("Status", lambda c, r, _: c.get("dBInstanceStatus")),
        ("Endpoint", lambda c, r, _: _safe_get(c, ["endpoint", "address"])),
    ],
)

# === S3 BUCKET ===
_register(
    "AWS::S3::Bucket",
    [
        ("Region", lambda c, r, _: c.get("region")),
        (
            "Versioning",
            lambda c, r, _: _safe_get(c, ["versioning", "status"]) or _safe_get(c, ["versioningConfiguration", "status"]),
        ),
        (
            "Encryption",
            lambda c, r, _: _safe_get(c, ["bucketEncryption", "ServerSideEncryptionConfiguration"]),
        ),
        (
            "Public Access Block",
            lambda c, r, _: c.get("publicAccessBlockConfiguration"),
        ),
        ("Lifecycle Rules", lambda c, r, _: c.get("lifecycleConfiguration")),
        ("Object Count", lambda c, r, _: c.get("numberOfObjects")),
        ("Size (Bytes)", lambda c, r, _: c.get("size")),
    ],
)

# === LAMBDA FUNCTION ===
_register(
    "AWS::Lambda::Function",
    [
        ("Runtime", lambda c, r, _: c.get("runtime")),
        ("Handler", lambda c, r, _: c.get("handler")),
        ("Memory (MB)", lambda c, r, _: c.get("memorySize")),
        ("Timeout (s)", lambda c, r, _: c.get("timeout")),
        ("IAM Role", lambda c, r, _: c.get("role")),
        ("Last Modified", lambda c, r, _: c.get("lastModified")),
        (
            "VPC Config",
            lambda c, r, _: _safe_get(c, ["vpcConfig", "subnetIds"]) or _safe_get(c, ["vpcConfig", "VpcId"]),
        ),
        ("Security Groups", lambda c, r, _: _safe_get(c, ["vpcConfig", "securityGroupIds"])),
        ("Code Size (bytes)", lambda c, r, _: c.get("codeSize")),
    ],
)

# === NETWORK INTERFACE ===
_register(
    "AWS::EC2::NetworkInterface",
    [
        ("Status", lambda c, r, _: c.get("status")),
        ("Private IP", lambda c, r, _: c.get("privateIpAddress")),
        ("Public IP", lambda c, r, _: _safe_get(c, ["association", "publicIp"])),
        ("Subnet", lambda c, r, _: c.get("subnetId")),
        ("VPC", lambda c, r, _: c.get("vpcId")),
        ("Attached Instance", lambda c, r, _: _safe_get(c, ["attachment", "instanceId"])),
        ("Security Groups", lambda c, r, _: _security_groups_from(c)),
    ],
)

# === ECS CLUSTER ===
_register(
    "AWS::ECS::Cluster",
    [
        ("Status", lambda c, r, _: c.get("status")),
        ("Registered Container Instances", lambda c, r, _: c.get("registeredContainerInstancesCount")),
        ("Running Tasks", lambda c, r, _: c.get("runningTasksCount")),
        ("Pending Tasks", lambda c, r, _: c.get("pendingTasksCount")),
        ("Active Services", lambda c, r, _: c.get("activeServicesCount")),
        ("Capacity Providers", lambda c, r, _: c.get("capacityProviders")),
    ],
)

# === EKS CLUSTER ===
_register(
    "AWS::EKS::Cluster",
    [
        ("Version", lambda c, r, _: c.get("version")),
        ("Status", lambda c, r, _: c.get("status")),
        ("Platform Version", lambda c, r, _: c.get("platformVersion")),
        ("Endpoint", lambda c, r, _: c.get("endpoint")),
        (
            "Subnet IDs",
            lambda c, r, _: _safe_get(c, ["resourcesVpcConfig", "subnetIds"]),
        ),
        (
            "Security Groups",
            lambda c, r, _: _safe_get(c, ["resourcesVpcConfig", "securityGroupIds"]),
        ),
        (
            "Public Access",
            lambda c, r, _: _safe_get(c, ["resourcesVpcConfig", "endpointPublicAccess"]),
        ),
        (
            "Private Access",
            lambda c, r, _: _safe_get(c, ["resourcesVpcConfig", "endpointPrivateAccess"]),
        ),
    ],
)

# === LOAD BALANCERS ===
_register(
    "AWS::ElasticLoadBalancing::LoadBalancer",
    [
        ("Scheme", lambda c, r, _: c.get("scheme")),
        ("DNS Name", lambda c, r, _: c.get("dnsName")),
        ("VPC", lambda c, r, _: c.get("vpcId")),
        ("Availability Zones", lambda c, r, _: c.get("availabilityZones")),
        ("Security Groups", lambda c, r, _: c.get("securityGroups")),
    ],
)

_register(
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    [
        ("Type", lambda c, r, _: c.get("type")),
        ("Scheme", lambda c, r, _: c.get("scheme")),
        ("State", lambda c, r, _: _safe_get(c, ["state", "code"])),
        ("DNS Name", lambda c, r, _: c.get("dnsName")),
        ("IP Address Type", lambda c, r, _: c.get("ipAddressType")),
        ("Security Groups", lambda c, r, _: c.get("securityGroups")),
        ("Subnets", lambda c, r, _: c.get("availabilityZones")),
    ],
)

# === KMS KEY ===
_register(
    "AWS::KMS::Key",
    [
        ("Key State", lambda c, r, _: c.get("keyState")),
        ("Key Usage", lambda c, r, _: c.get("keyUsage")),
        ("Origin", lambda c, r, _: c.get("origin")),
        ("Key Manager", lambda c, r, _: c.get("keyManager")),
        ("Multi-Region", lambda c, r, _: c.get("multiRegion")),
        ("Rotation Enabled", lambda c, r, _: c.get("rotationEnabled")),
        ("Description", lambda c, r, _: c.get("description")),
    ],
)

# === FSX FILE SYSTEM ===
_register(
    "AWS::FSx::FileSystem",
    [
        ("Type", lambda c, r, _: c.get("fileSystemType")),
        ("Storage Capacity", lambda c, r, _: c.get("storageCapacity")),
        ("Storage Type", lambda c, r, _: c.get("storageType")),
        ("Lifecycle", lambda c, r, _: c.get("lifecycle")),
        ("Subnet IDs", lambda c, r, _: c.get("subnetIds")),
        (
            "Network Interfaces",
            lambda c, r, _: c.get("networkInterfaceIds"),
        ),
        ("KMS Key", lambda c, r, _: c.get("kmsKeyId")),
    ],
)

# === BACKUP VAULT ===
_register(
    "AWS::Backup::BackupVault",
    [
        ("Locked", lambda c, r, _: c.get("locked")),
        ("Min Retention (days)", lambda c, r, _: c.get("minRetentionDays")),
        ("Max Retention (days)", lambda c, r, _: c.get("maxRetentionDays")),
        ("Encryption Key", lambda c, r, _: c.get("encryptionKeyArn")),
        ("Recovery Points", lambda c, r, _: c.get("numberOfRecoveryPoints")),
    ],
)

_register(
    "AWS::Backup::BackupPlan",
    [
        ("Plan Name", lambda c, r, _: _safe_get(c, ["backupPlan", "backupPlanName"])),
        ("Plan ARN", lambda c, r, _: _safe_get(c, ["backupPlan", "backupPlanArn"])),
        ("Rule Count", lambda c, r, _: len(_backup_rules(c))),
        ("Rule Names", lambda c, r, _: _backup_rule_names(c)),
        ("Target Vaults", lambda c, r, _: _backup_rule_vaults(c)),
        ("Advanced Settings", lambda c, r, _: _backup_advanced_settings(c)),
    ],
)

# === WORKSPACES ===
_register(
    "AWS::WorkSpaces::Workspace",
    [
        ("User", lambda c, r, _: c.get("userName")),
        ("State", lambda c, r, _: c.get("state")),
        ("Computer", lambda c, r, _: c.get("computerName")),
        ("IP Address", lambda c, r, _: c.get("ipAddress")),
        ("Subnet", lambda c, r, _: c.get("subnetId")),
        (
            "Compute Type",
            lambda c, r, _: _safe_get(c, ["workspaceProperties", "computeTypeName"]),
        ),
        (
            "Root Volume (GiB)",
            lambda c, r, _: _safe_get(c, ["workspaceProperties", "rootVolumeSizeGib"]),
        ),
        (
            "User Volume (GiB)",
            lambda c, r, _: _safe_get(c, ["workspaceProperties", "userVolumeSizeGib"]),
        ),
        ("Bundle ID", lambda c, r, _: c.get("bundleId")),
        ("Directory ID", lambda c, r, _: c.get("directoryId")),
        ("Volume Encryption Key", lambda c, r, _: c.get("volumeEncryptionKey")),
        (
            "Running Mode",
            lambda c, r, _: _safe_get(c, ["workspaceProperties", "runningMode"]),
        ),
        (
            "Auto Stop (min)",
            lambda c, r, _: _safe_get(c, ["workspaceProperties", "runningModeAutoStopTimeoutInMinutes"]),
        ),
    ],
)

# === ROUTE53 HOSTED ZONE ===
_register(
    "AWS::Route53::HostedZone",
    [
        ("Name", lambda c, r, _: c.get("name")),
        ("Private Zone", lambda c, r, _: _safe_get(c, ["config", "privateZone"])),
        ("Record Sets", lambda c, r, _: c.get("resourceRecordSetCount")),
        (
            "Linked VPCs",
            lambda c, r, _: [
                f"{vpc.get('vPCId')} ({vpc.get('vPCRegion')})" for vpc in c.get("vPCs", []) or []
            ],
        ),
    ],
)

# === NAT GATEWAY ===
_register(
    "AWS::EC2::NatGateway",
    [
        ("State", lambda c, r, _: c.get("state")),
        ("Connectivity", lambda c, r, _: c.get("connectivityType")),
        ("Subnet", lambda c, r, _: c.get("subnetId")),
        ("VPC", lambda c, r, _: c.get("vpcId")),
        (
            "Public IPs",
            lambda c, r, _: [addr.get("publicIp") for addr in c.get("natGatewayAddresses", []) or []],
        ),
        (
            "Private IPs",
            lambda c, r, _: [addr.get("privateIp") for addr in c.get("natGatewayAddresses", []) or []],
        ),
        (
            "Network Interfaces",
            lambda c, r, _: [addr.get("networkInterfaceId") for addr in c.get("natGatewayAddresses", []) or []],
        ),
        ("Create Time", lambda c, r, _: c.get("createTime")),
    ],
)

# === ELASTICACHE ===
_register(
    "AWS::ElastiCache::CacheCluster",
    [
        ("Engine", lambda c, r, _: c.get("engine")),
        ("Engine Version", lambda c, r, _: c.get("engineVersion")),
        ("Node Type", lambda c, r, _: c.get("cacheNodeType")),
        ("Nodes", lambda c, r, _: c.get("numCacheNodes")),
        ("AZ", lambda c, r, _: c.get("preferredAvailabilityZone")),
        ("Subnet Group", lambda c, r, _: c.get("cacheSubnetGroupName")),
        (
            "Security Groups",
            lambda c, r, _: [sg.get("securityGroupId") for sg in c.get("securityGroups", []) or []],
        ),
    ],
)

# === OPENSEARCH ===
_register(
    "AWS::OpenSearch::Domain",
    [
        ("Engine Version", lambda c, r, _: c.get("engineVersion")),
        (
            "Instance Type",
            lambda c, r, _: _safe_get(c, ["clusterConfig", "instanceType"]),
        ),
        (
            "Instance Count",
            lambda c, r, _: _safe_get(c, ["clusterConfig", "instanceCount"]),
        ),
        (
            "Dedicated Master",
            lambda c, r, _: _safe_get(c, ["clusterConfig", "dedicatedMasterEnabled"]),
        ),
        (
            "Zone Awareness",
            lambda c, r, _: _safe_get(c, ["clusterConfig", "zoneAwarenessEnabled"]),
        ),
        (
            "Encryption at Rest",
            lambda c, r, _: _safe_get(c, ["encryptionAtRestOptions", "enabled"]),
        ),
        (
            "Node-to-Node Encryption",
            lambda c, r, _: _safe_get(c, ["nodeToNodeEncryptionOptions", "enabled"]),
        ),
        (
            "VPC",
            lambda c, r, _: _safe_get(c, ["vPCOptions", "vpcId"]),
        ),
        ("Subnets", lambda c, r, _: _safe_get(c, ["vPCOptions", "subnetIds"])),
    ],
)

# === ECS SERVICE ===
_register(
    "AWS::ECS::Service",
    [
        ("Cluster ARN", lambda c, r, _: c.get("clusterArn")),
        ("Launch Type", lambda c, r, _: c.get("launchType")),
        ("Task Definition", lambda c, r, _: c.get("taskDefinition")),
        ("Desired Count", lambda c, r, _: c.get("desiredCount")),
        ("Running Count", lambda c, r, _: c.get("runningCount")),
        ("Pending Count", lambda c, r, _: c.get("pendingCount")),
        ("Scheduling Strategy", lambda c, r, _: c.get("schedulingStrategy")),
        ("Assign Public IP", lambda c, r, _: _awsvpc_assign_public_ip(c)),
        ("Subnets", lambda c, r, _: _awsvpc_subnets(c)),
        ("Security Groups", lambda c, r, _: _awsvpc_security_groups(c)),
        (
            "Load Balancers",
            lambda c, r, _: [
                lb.get("targetGroupArn") or lb.get("loadBalancerName")
                for lb in c.get("loadBalancers", []) or []
            ],
        ),
    ],
)

# === EKS NODE GROUP ===
_register(
    "AWS::EKS::Nodegroup",
    [
        ("Cluster Name", lambda c, r, _: c.get("clusterName")),
        ("Nodegroup", lambda c, r, _: c.get("nodegroupName")),
        ("Status", lambda c, r, _: c.get("status")),
        ("Capacity Type", lambda c, r, _: c.get("capacityType")),
        ("Instance Types", lambda c, r, _: c.get("instanceTypes")),
        ("Subnets", lambda c, r, _: c.get("subnets")),
        ("Desired Size", lambda c, r, _: _safe_get(c, ["scalingConfig", "desiredSize"])),
        ("Min Size", lambda c, r, _: _safe_get(c, ["scalingConfig", "minSize"])),
        ("Max Size", lambda c, r, _: _safe_get(c, ["scalingConfig", "maxSize"])),
        ("AMI Type", lambda c, r, _: c.get("amiType")),
        ("IAM Role", lambda c, r, _: c.get("nodeRole")),
    ],
)
