"""Best-effort account-local inventory using read-only AWS service APIs.

AWS Config Aggregators and Resource Explorer provide the broadest inventory, but
are not always available to an account-level role. This adapter uses service
list/describe APIs as a fallback and isolates failures per service.
"""

import logging
from dataclasses import replace
from datetime import datetime
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aws_ri.application.ports.aws_ports import InventoryPort
from aws_ri.domain.inventory.resource import Resource, ResourceTag

logger = logging.getLogger(__name__)


class AccountLocalInventoryAdapter(InventoryPort):
    """Collect resources visible to the current account-local principal."""

    def __init__(self, session: boto3.Session, account_id: str):
        self.session = session
        self.account_id = account_id
        self.collection_status: dict[str, str] = {}

    def get_aggregator_name(self) -> Optional[str]:
        return "Account-local service APIs"

    def fetch_resources(self, aggregator_name: str, account_ids: Optional[list[str]] = None,
                        regions: Optional[list[str]] = None, resource_types: Optional[list[str]] = None,
                        start_time=None, end_time=None) -> list[Resource]:
        if account_ids and self.account_id not in account_ids:
            return []
        target_regions = regions or self._enabled_regions()
        resources: list[Resource] = []
        for region in target_regions:
            resources.extend(self._collect_region(region))
        resources.extend(self._collect_global())
        resources = self._enrich_resources(resources, target_regions)
        if resource_types:
            resources = [r for r in resources if r.resource_type in resource_types]
        logger.info("Account-local inventory collected %s resources across %s regions", len(resources), len(target_regions))
        return resources

    def _enrich_resources(self, resources: list[Resource], regions: list[str]) -> list[Resource]:
        """Merge centralized tags and expose common governance metadata."""
        tags_by_arn: dict[str, tuple[ResourceTag, ...]] = {}
        tag_mapping_count = 0
        for region in regions:
            try:
                client = self.session.client("resourcegroupstaggingapi", region_name=region)
                for page in client.get_paginator("get_resources").paginate(ResourcesPerPage=100):
                    for item in page.get("ResourceTagMappingList", []):
                        tag_mapping_count += 1
                        arn = item.get("ResourceARN")
                        if arn:
                            tags_by_arn[arn] = tuple(ResourceTag(str(t.get("Key")), str(t.get("Value", ""))) for t in item.get("Tags", []) if t.get("Key"))
                self.collection_status["Resource Groups Tagging API"] = "Collected" if tag_mapping_count else "No resources"
            except (ClientError, BotoCoreError) as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                self.collection_status["Resource Groups Tagging API"] = "Denied" if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"} else "Unavailable"
                logger.warning("Skipping Resource Groups Tagging API in %s: %s", region, exc)
            except Exception as exc:
                self.collection_status["Resource Groups Tagging API"] = "Unavailable"
                logger.warning("Skipping Resource Groups Tagging API in %s: %s", region, exc)

        enriched: list[Resource] = []
        dedicated_tag_count = 0
        for resource in resources:
            config = dict(resource.configuration or {})
            merged_tags = tags_by_arn.get(resource.arn, resource.tags) if resource.arn else resource.tags
            dedicated = self._dedicated_tags(resource)
            if dedicated:
                dedicated_tag_count += 1
                merged_tags = tuple({tag.key: tag for tag in (*merged_tags, *dedicated)}.values())
            if merged_tags:
                merged_tags = tuple({tag.key: tag for tag in (*resource.tags, *merged_tags)}.values())
            metadata = self._common_metadata(resource, config)
            config["inventory_enrichment"] = metadata
            enriched.append(replace(resource, tags=merged_tags, configuration=config,
                                    creation_time=self._parse_datetime(metadata.get("creation_date")),
                                    status=resource.status or metadata.get("state") or metadata.get("health")))
        if "Resource Groups Tagging API" not in self.collection_status:
            self.collection_status["Resource Groups Tagging API"] = "No resources"
        self.collection_status["Dedicated tag APIs"] = "Collected" if dedicated_tag_count else "No resources"
        return enriched

    def _dedicated_tags(self, resource: Resource) -> tuple[ResourceTag, ...]:
        """Use service tag APIs for resources not returned by Tagging API."""
        try:
            values = []
            if resource.resource_type == "AWS::S3::Bucket":
                data = self.session.client("s3", region_name="us-east-1").get_bucket_tagging(Bucket=resource.resource_id)
                values = data.get("TagSet", [])
            elif resource.resource_type == "AWS::Lambda::Function" and resource.arn:
                values = [{"Key": k, "Value": v} for k, v in self.session.client("lambda", region_name=resource.region).list_tags(Resource=resource.arn).get("Tags", {}).items()]
            elif resource.resource_type in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"} and resource.arn:
                values = self.session.client("rds", region_name=resource.region).list_tags_for_resource(ResourceName=resource.arn).get("TagList", [])
            elif resource.resource_type == "AWS::EKS::Cluster" and resource.arn:
                values = [{"Key": k, "Value": v} for k, v in self.session.client("eks", region_name=resource.region).list_tags_for_resource(resourceArn=resource.arn).get("tags", {}).items()]
            elif resource.resource_type == "AWS::IAM::Role":
                values = self.session.client("iam", region_name="us-east-1").list_role_tags(RoleName=resource.resource_id).get("Tags", [])
            elif resource.resource_type == "AWS::IAM::User":
                values = self.session.client("iam", region_name="us-east-1").list_user_tags(UserName=resource.resource_id).get("Tags", [])
            return tuple(ResourceTag(str(t.get("Key")), str(t.get("Value", ""))) for t in values if t.get("Key"))
        except Exception as exc:
            logger.debug("Dedicated tags unavailable for %s: %s", resource.resource_id, exc)
            return tuple()

    @staticmethod
    def _common_metadata(resource: Resource, config: dict[str, Any]) -> dict[str, Any]:
        def first(*keys):
            for key in keys:
                value = config.get(key)
                if value not in (None, "", [], {}):
                    return value
            return ""

        relationships: dict[str, Any] = {}
        for key in ("VpcId", "SubnetId", "VpcId", "NetworkInterfaceId", "InstanceId", "ClusterArn", "Role", "SecurityGroupIds", "SecurityGroups", "Groups"):
            if config.get(key):
                relationships[key] = config[key]
        metadata = {
            "creation_date": first("CreationDate", "CreateTime", "createdAt", "CreationTime", "LaunchTime", "LastModified", "createdDate"),
            "encryption": first("Encrypted", "encryptionEnabled", "EncryptionEnabled", "EncryptionType", "encryptionConfiguration", "SSEAlgorithm", "BucketKeyEnabled"),
            "public_exposure": first("PubliclyAccessible", "PublicAccess", "publicAccessBlock", "BlockPublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets", "IgnorePublicAcls", "AssignPublicIp"),
            "owner": first("OwnerId", "ownerId", "AccountId", "RegistryId") or resource.account_id,
            "state": first("State", "Status", "status", "StackStatus", "StateName"),
            "health": first("HealthStatus", "Health", "healthStatus", "DBInstanceStatus", "ClusterStatus", "State"),
            "relationships": relationships,
            "dependencies": {key: config[key] for key in ("Role", "Layers", "LoadBalancerArns", "TargetGroupArns", "VpcSecurityGroupIds", "SubnetIds") if config.get(key)},
        }
        return metadata

    @staticmethod
    def _parse_datetime(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None

    def _enabled_regions(self) -> list[str]:
        home = self.session.region_name or "us-east-1"
        try:
            response = self.session.client("ec2", region_name=home).describe_regions(AllRegions=False)
            return sorted({r["RegionName"] for r in response.get("Regions", [])}) or [home]
        except (ClientError, BotoCoreError) as exc:
            logger.warning("Unable to discover enabled regions; using %s: %s", home, exc)
            return [home]

    def _collect_region(self, region: str) -> list[Resource]:
        result: list[Resource] = []
        result += self._collect_ec2(region)
        result += self._collect_networking(region)
        result += self._collect_lambda(region)
        result += self._collect_rds(region)
        result += self._collect_ecs(region)
        result += self._collect_eks(region)
        result += self._collect_dynamodb(region)
        result += self._collect_cloudformation(region)
        result += self._collect_messaging(region)
        result += self._collect_platform(region)
        result += self._collect_extended(region)
        result += self._collect_additional(region)
        return result

    def _collect_additional(self, region: str) -> list[Resource]:
        """Collect first-class resources not covered by the core collectors.

        This method intentionally contains only services that do not already have
        a collector above.  Each service is isolated through ``_safe`` so an
        account role or SCP denial cannot hide resources from other services.
        Values and secret material are never requested from Secrets Manager or
        SSM; only metadata is collected.
        """
        result: list[Resource] = []

        result += self._safe("Secrets Manager resources", lambda: [
            self._resource("AWS::SecretsManager::Secret", region, item["ARN"], item.get("Name"), item.get("ARN"), config=item)
            for page in self.session.client("secretsmanager", region_name=region).get_paginator("list_secrets").paginate()
            for item in page.get("SecretList", []) if item.get("ARN")
        ])
        result += self._safe("SSM Parameter Store resources", lambda: [
            self._resource("AWS::SSM::Parameter", region, item["Name"], item["Name"], config=item)
            for page in self.session.client("ssm", region_name=region).get_paginator("describe_parameters").paginate()
            for item in page.get("Parameters", []) if item.get("Name")
        ])

        def kms_resources() -> list[Resource]:
            client = self.session.client("kms", region_name=region)
            aliases = {a.get("TargetKeyId"): a.get("AliasName") for page in client.get_paginator("list_aliases").paginate()
                       for a in page.get("Aliases", []) if a.get("TargetKeyId")}
            values = []
            for page in client.get_paginator("list_keys").paginate():
                for key in page.get("Keys", []):
                    key_id = key.get("KeyId")
                    if not key_id:
                        continue
                    details = client.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    details = {**details, "AliasName": aliases.get(key_id, "")}
                    arn = details.get("Arn") or key.get("KeyArn")
                    values.append(self._resource("AWS::KMS::Key", region, key_id, aliases.get(key_id) or key_id, arn, config=details,
                                                 status=details.get("KeyState")))
            return values
        result += self._safe("KMS keys", kms_resources)

        def eventbridge_resources() -> list[Resource]:
            client = self.session.client("events", region_name=region)
            values = []
            for page in client.get_paginator("list_rules").paginate():
                for rule in page.get("Rules", []):
                    name = rule.get("Name")
                    if not name:
                        continue
                    config = dict(rule)
                    config["Targets"] = client.list_targets_by_rule(Rule=name).get("Targets", [])
                    values.append(self._resource("AWS::Events::Rule", region, name, name, rule.get("Arn"), config=config,
                                                 status=rule.get("State")))
            return values
        result += self._safe("EventBridge rules", eventbridge_resources)

        def cloudwatch_alarms() -> list[Resource]:
            client = self.session.client("cloudwatch", region_name=region)
            values = []
            for page in client.get_paginator("describe_alarms").paginate():
                for key in ("MetricAlarms", "CompositeAlarms"):
                    for alarm in page.get(key, []):
                        name = alarm.get("AlarmName")
                        if name:
                            values.append(self._resource("AWS::CloudWatch::Alarm", region, name, name, alarm.get("AlarmArn"),
                                                         config=alarm, status=alarm.get("StateValue")))
            return values
        result += self._safe("CloudWatch alarms", cloudwatch_alarms)

        result += self._safe("SageMaker endpoints", lambda: [
            self._resource("AWS::SageMaker::Endpoint", region, item["EndpointName"], item["EndpointName"],
                           config=item, status=item.get("EndpointStatus"))
            for page in self.session.client("sagemaker", region_name=region).get_paginator("list_endpoints").paginate()
            for item in page.get("Endpoints", []) if item.get("EndpointName")
        ])
        result += self._safe("Amplify apps", lambda: [
            self._resource("AWS::Amplify::App", region, item["appId"], item.get("name") or item["appId"], item.get("appArn"),
                           config=item, status=item.get("status"))
            for page in self.session.client("amplify", region_name=region).get_paginator("list_apps").paginate()
            for item in page.get("apps", []) if item.get("appId")
        ])
        result += self._safe("Cognito user pools", lambda: [
            self._resource("AWS::Cognito::UserPool", region, item["Id"], item.get("Name") or item["Id"],
                           f"arn:aws:cognito-idp:{region}:{self.account_id}:userpool/{item['Id']}", config=item)
            for page in self.session.client("cognito-idp", region_name=region).get_paginator("list_user_pools").paginate(MaxResults=60)
            for item in page.get("UserPools", []) if item.get("Id")
        ])

        def load_balancers() -> list[Resource]:
            client = self.session.client("elbv2", region_name=region)
            values = []
            for page in client.get_paginator("describe_load_balancers").paginate():
                for item in page.get("LoadBalancers", []):
                    arn = item.get("LoadBalancerArn")
                    if not arn:
                        continue
                    config = dict(item)
                    config["Listeners"] = client.describe_listeners(LoadBalancerArn=arn).get("Listeners", [])
                    values.append(self._resource("AWS::ElasticLoadBalancingV2::LoadBalancer", region, arn,
                                                 item.get("LoadBalancerName"), arn, config=config,
                                                 status=item.get("State", {}).get("Code")))
                    for target_page in client.get_paginator("describe_target_groups").paginate(LoadBalancerArn=arn):
                        for target in target_page.get("TargetGroups", []):
                            target_arn = target.get("TargetGroupArn")
                            if target_arn:
                                target_config = dict(target)
                                target_config["TargetHealth"] = client.describe_target_health(
                                    TargetGroupArn=target_arn).get("TargetHealthDescriptions", [])
                                values.append(self._resource("AWS::ElasticLoadBalancingV2::TargetGroup", region, target_arn,
                                                             target.get("TargetGroupName"), target_arn, config=target_config))
            return values
        result += self._safe("Elastic Load Balancing resources", load_balancers)

        result += self._safe("EFS file systems", lambda: [
            self._resource("AWS::EFS::FileSystem", region, item["FileSystemId"], item.get("Name") or item["FileSystemId"],
                           item.get("FileSystemArn"), config=item, status=item.get("LifeCycleState"))
            for page in self.session.client("efs", region_name=region).get_paginator("describe_file_systems").paginate()
            for item in page.get("FileSystems", []) if item.get("FileSystemId")
        ])
        def efs_children() -> list[Resource]:
            client = self.session.client("efs", region_name=region)
            values = []
            for page in client.get_paginator("describe_file_systems").paginate():
                for filesystem in page.get("FileSystems", []):
                    fs_id = filesystem.get("FileSystemId")
                    if not fs_id:
                        continue
                    for child_page in client.get_paginator("describe_mount_targets").paginate(FileSystemId=fs_id):
                        for target in child_page.get("MountTargets", []):
                            target_id = target.get("MountTargetId")
                            if target_id:
                                values.append(self._resource("AWS::EFS::MountTarget", region, target_id, target_id,
                                                             config=target, status=target.get("LifeCycleState")))
                    for child_page in client.get_paginator("describe_access_points").paginate(FileSystemId=fs_id):
                        for access_point in child_page.get("AccessPoints", []):
                            access_id = access_point.get("AccessPointId")
                            if access_id:
                                values.append(self._resource("AWS::EFS::AccessPoint", region, access_id, access_id,
                                                             access_point.get("AccessPointArn"), config=access_point,
                                                             status=access_point.get("LifeCycleState")))
            return values
        result += self._safe("EFS mount targets and access points", efs_children)
        result += self._safe("FSx file systems", lambda: [
            self._resource("AWS::FSx::FileSystem", region, item["FileSystemId"], item.get("FileSystemId"), item.get("ResourceARN"),
                           config=item, status=item.get("Lifecycle"))
            for page in self.session.client("fsx", region_name=region).get_paginator("describe_file_systems").paginate()
            for item in page.get("FileSystems", []) if item.get("FileSystemId")
        ])

        database_services = [
            ("neptune", "describe_db_clusters", "DBClusters", "AWS::Neptune::DBCluster", "DBClusterIdentifier", "DBClusterArn", "Status"),
            ("docdb", "describe_db_clusters", "DBClusters", "AWS::DocDB::DBCluster", "DBClusterIdentifier", "DBClusterArn", "Status"),
            ("timestream-write", "list_databases", "Databases", "AWS::Timestream::Database", "DatabaseName", "Arn", None),
            ("keyspaces", "list_keyspaces", "keyspaces", "AWS::Cassandra::Keyspace", "keyspaceName", "resourceArn", None),
            ("qldb", "list_ledgers", "Ledgers", "AWS::QLDB::Ledger", "Name", "Arn", "State"),
        ]
        for service, method, response_key, resource_type, id_key, arn_key, status_key in database_services:
            def collect_database(service=service, method=method, response_key=response_key, resource_type=resource_type,
                                 id_key=id_key, arn_key=arn_key, status_key=status_key):
                client = self.session.client(service, region_name=region)
                values = []
                for page in client.get_paginator(method).paginate():
                    for item in page.get(response_key, []):
                        identifier = item.get(id_key)
                        if identifier:
                            values.append(self._resource(resource_type, region, identifier, identifier, item.get(arn_key),
                                                         config=item, status=item.get(status_key) if status_key else None))
                return values
            result += self._safe(f"{service} resources", collect_database)

        ec2 = self.session.client("ec2", region_name=region)
        networking = [
            ("AWS::EC2::VPCEndpoint", "describe_vpc_endpoints", "VpcEndpoints", "VpcEndpointId", "VpcEndpointId", "State"),
            ("AWS::EC2::NetworkAcl", "describe_network_acls", "NetworkAcls", "NetworkAclId", "NetworkAclId", None),
            ("AWS::EC2::TransitGateway", "describe_transit_gateways", "TransitGateways", "TransitGatewayId", "TransitGatewayId", "State"),
            ("AWS::EC2::VPCPeeringConnection", "describe_vpc_peering_connections", "VpcPeeringConnections", "VpcPeeringConnectionId", "VpcPeeringConnectionId", "Status.Code"),
            ("AWS::EC2::VPNConnection", "describe_vpn_connections", "VpnConnections", "VpnConnectionId", "VpnConnectionId", "State"),
            ("AWS::EC2::CustomerGateway", "describe_customer_gateways", "CustomerGateways", "CustomerGatewayId", "CustomerGatewayId", "State"),
        ]
        for resource_type, method, response_key, id_key, name_key, status_key in networking:
            def collect_networking(resource_type=resource_type, method=method, response_key=response_key,
                                   id_key=id_key, name_key=name_key, status_key=status_key):
                values = []
                for page in ec2.get_paginator(method).paginate():
                    for item in page.get(response_key, []):
                        identifier = item.get(id_key)
                        if not identifier:
                            continue
                        status = item.get(status_key) if status_key and "." not in status_key else None
                        if status_key == "Status.Code":
                            status = item.get("Status", {}).get("Code")
                        arn = item.get("TransitGatewayArn") or item.get("VpcEndpointId")
                        values.append(self._resource(resource_type, region, identifier, item.get(name_key), arn, item.get("Tags"), status, item))
                return values
            result += self._safe(f"{resource_type} resources", collect_networking)
        return result

    def _collect_extended(self, region: str) -> list[Resource]:
        """Collect additional first-class service resources when the role allows it.

        These calls intentionally remain isolated: an SCP or an un-enabled service
        must not prevent the rest of the account inventory from completing.
        """
        result: list[Resource] = []
        definitions = [
            ("acm", "list_certificates", "AWS::ACM::Certificate", "CertificateSummaryList", "CertificateArn", "DomainName"),
            ("wafv2", "list_web_acls", "AWS::WAFv2::WebACL", "WebACLs", "ARN", "Name"),
            ("cloudtrail", "describe_trails", "AWS::CloudTrail::Trail", "trailList", "TrailARN", "Name"),
            ("kinesis", "list_streams", "AWS::Kinesis::Stream", "StreamNames", None, None),
            ("redshift", "describe_clusters", "AWS::Redshift::Cluster", "Clusters", "ClusterIdentifier", "ClusterIdentifier"),
            ("glue", "get_databases", "AWS::Glue::Database", "DatabaseList", "Name", "Name"),
            ("athena", "list_work_groups", "AWS::Athena::WorkGroup", "WorkGroups", "Name", "Name"),
            ("sagemaker", "list_notebook_instances", "AWS::SageMaker::NotebookInstance", "NotebookInstances", "NotebookInstanceName", "NotebookInstanceName"),
            ("emr", "list_clusters", "AWS::EMR::Cluster", "Clusters", "Id", "Name"),
            ("kafka", "list_clusters", "AWS::MSK::Cluster", "ClusterInfoList", "ClusterArn", "ClusterName"),
            ("elasticbeanstalk", "describe_environments", "AWS::ElasticBeanstalk::Environment", "Environments", "EnvironmentId", "EnvironmentName"),
            ("apprunner", "list_services", "AWS::AppRunner::Service", "ServiceSummaryList", "ServiceArn", "ServiceName"),
        ]
        for service, method, resource_type, response_key, id_key, name_key in definitions:
            def collect(service=service, method=method, resource_type=resource_type,
                        response_key=response_key, id_key=id_key, name_key=name_key):
                client = self.session.client(service, region_name=region)
                if service in {"cloudtrail", "elasticbeanstalk", "athena", "apprunner"}:
                    response = getattr(client, method)()
                    pages = [response]
                elif service == "wafv2":
                    response = client.list_web_acls(Scope="REGIONAL")
                    pages = [response]
                else:
                    pages = client.get_paginator(method).paginate()
                items = [item for page in pages for item in page.get(response_key, [])]
                resources = []
                for item in items:
                    if id_key is None:
                        identifier = str(item)
                        name = identifier
                        arn = f"arn:aws:kinesis:{region}:{self.account_id}:stream/{identifier}"
                        config = {"Name": identifier}
                    else:
                        identifier = item.get(id_key)
                        if not identifier:
                            continue
                        name = item.get(name_key) if name_key else identifier
                        arn = item.get("ARN") or item.get("Arn") or item.get("ClusterArn") or item.get("ServiceArn")
                        config = item
                    resources.append(self._resource(resource_type, region, str(identifier), name, arn, config=config,
                                                    status=item.get("Status") or item.get("State") or item.get("ClusterStatus")))
                return resources
            result += self._safe(f"{service} resources", collect)
        # Detail enrichment for certificates makes expiration and validation state
        # visible in the inventory sheet without requiring a separate posture run.
        result = self._safe_detail(result, "acm", region, "CertificateArn", "describe_certificate", "Certificate")
        return result

    def _safe_detail(self, resources, service, region, id_key, method, response_key):
        try:
            client = self.session.client(service, region_name=region)
        except Exception as exc:
            self.collection_status[f"{service} detail enrichment"] = "Unavailable"
            logger.warning("Unable to initialize %s detail enrichment: %s", service, exc)
            return resources
        enriched = []
        for resource in resources:
            if resource.resource_type != "AWS::ACM::Certificate" or not resource.arn:
                enriched.append(resource)
                continue
            try:
                details = getattr(client, method)(Certificate=resource.arn).get(response_key, {})
                enriched.append(replace(resource, configuration={**(resource.configuration or {}), **details},
                                         creation_time=self._parse_datetime(details.get("CreatedAt")),
                                         status=details.get("Status") or resource.status))
            except Exception as exc:
                logger.warning("Unable to enrich %s: %s", resource.resource_id, exc)
                enriched.append(resource)
        self.collection_status[f"{service} detail enrichment"] = "Collected" if enriched else "No resources"
        return enriched

    def _collect_ec2(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region_name=region)
        result = self._safe("EC2 instances", lambda: [
            self._resource("AWS::EC2::Instance", region, i["InstanceId"], self._tag_name(i.get("Tags")),
                           f"arn:aws:ec2:{region}:{self.account_id}:instance/{i['InstanceId']}", i.get("Tags"), i.get("State", {}).get("Name"), i)
            for page in ec2.get_paginator("describe_instances").paginate()
            for reservation in page.get("Reservations", []) for i in reservation.get("Instances", [])
        ])
        result += self._safe("EBS volumes", lambda: [
            self._resource("AWS::EC2::Volume", region, v["VolumeId"], arn=f"arn:aws:ec2:{region}:{self.account_id}:volume/{v['VolumeId']}", tags=v.get("Tags"), status=v.get("State"), config=v)
            for page in ec2.get_paginator("describe_volumes").paginate() for v in page.get("Volumes", [])
        ])
        result += self._safe("EC2 key pairs", lambda: [
            self._resource("AWS::EC2::KeyPair", region, k["KeyPairId"], k.get("KeyName"), config=k)
            for k in ec2.describe_key_pairs().get("KeyPairs", [])
        ])
        return result

    def _collect_networking(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region_name=region)
        result: list[Resource] = []
        specs = [
            ("AWS::EC2::VPC", "describe_vpcs", "Vpcs", "VpcId", "vpc"),
            ("AWS::EC2::Subnet", "describe_subnets", "Subnets", "SubnetId", "subnet"),
            ("AWS::EC2::RouteTable", "describe_route_tables", "RouteTables", "RouteTableId", "route-table"),
            ("AWS::EC2::NetworkInterface", "describe_network_interfaces", "NetworkInterfaces", "NetworkInterfaceId", "network-interface"),
            ("AWS::EC2::NatGateway", "describe_nat_gateways", "NatGateways", "NatGatewayId", "natgateway"),
            ("AWS::EC2::InternetGateway", "describe_internet_gateways", "InternetGateways", "InternetGatewayId", "internet-gateway"),
            ("AWS::EC2::SecurityGroup", "describe_security_groups", "SecurityGroups", "GroupId", "security-group"),
            ("AWS::EC2::EIP", "describe_addresses", "Addresses", "AllocationId", "eip-allocation"),
        ]
        for resource_type, method, key, id_key, arn_kind in specs:
            result += self._safe(resource_type, lambda method=method, key=key, id_key=id_key, resource_type=resource_type, arn_kind=arn_kind: [
                self._resource(resource_type, region, item[id_key], item.get("GroupName") or item.get("VpcId"),
                               f"arn:aws:ec2:{region}:{self.account_id}:{arn_kind}/{item[id_key]}", item.get("Tags"), item.get("State"), item)
                for page in ([ec2.describe_addresses()] if method == "describe_addresses" else ec2.get_paginator(method).paginate())
                for item in page.get(key, [])
            ])
        return result

    def _collect_lambda(self, region: str) -> list[Resource]:
        client = self.session.client("lambda", region_name=region)
        return self._safe("Lambda functions", lambda: [
            self._resource("AWS::Lambda::Function", region, f["FunctionName"], f["FunctionName"], f.get("FunctionArn"), config=f, status=f.get("State"))
            for page in client.get_paginator("list_functions").paginate() for f in page.get("Functions", [])
        ])

    def _collect_rds(self, region: str) -> list[Resource]:
        client = self.session.client("rds", region_name=region)
        result = self._safe("RDS instances", lambda: [
            self._resource("AWS::RDS::DBInstance", region, d["DBInstanceIdentifier"], d["DBInstanceIdentifier"], d.get("DBInstanceArn"), status=d.get("DBInstanceStatus"), config=d)
            for page in client.get_paginator("describe_db_instances").paginate() for d in page.get("DBInstances", [])
        ])
        result += self._safe("RDS clusters", lambda: [
            self._resource("AWS::RDS::DBCluster", region, d["DBClusterIdentifier"], d["DBClusterIdentifier"], d.get("DBClusterArn"), status=d.get("Status"), config=d)
            for page in client.get_paginator("describe_db_clusters").paginate() for d in page.get("DBClusters", [])
        ])
        return result

    def _collect_ecs(self, region: str) -> list[Resource]:
        client = self.session.client("ecs", region_name=region)
        result = self._safe("ECS clusters", lambda: [
            self._resource("AWS::ECS::Cluster", region, arn.rsplit("/", 1)[-1], arn.rsplit("/", 1)[-1], arn)
            for page in client.get_paginator("list_clusters").paginate() for arn in page.get("clusterArns", [])
        ])
        cluster_arns = [r.arn for r in result if r.arn]
        result += self._safe("ECS services", lambda: [
            self._resource("AWS::ECS::Service", region, arn.rsplit("/", 1)[-1], arn.rsplit("/", 1)[-1], arn)
            for cluster in cluster_arns for page in client.get_paginator("list_services").paginate(cluster=cluster)
            for arn in page.get("serviceArns", [])
        ])
        return result

    def _collect_eks(self, region: str) -> list[Resource]:
        client = self.session.client("eks", region_name=region)
        return self._safe("EKS clusters", lambda: [
            self._resource("AWS::EKS::Cluster", region, name, name, d.get("arn"), status=d.get("status"), config=d)
            for page in client.get_paginator("list_clusters").paginate() for name in page.get("clusters", [])
            for d in [client.describe_cluster(name=name).get("cluster", {})]
        ])

    def _collect_dynamodb(self, region: str) -> list[Resource]:
        client = self.session.client("dynamodb", region_name=region)
        return self._safe("DynamoDB tables", lambda: [
            self._resource("AWS::DynamoDB::Table", region, name, name, f"arn:aws:dynamodb:{region}:{self.account_id}:table/{name}")
            for page in client.get_paginator("list_tables").paginate() for name in page.get("TableNames", [])
        ])

    def _collect_cloudformation(self, region: str) -> list[Resource]:
        client = self.session.client("cloudformation", region_name=region)
        return self._safe("CloudFormation stacks", lambda: [
            self._resource("AWS::CloudFormation::Stack", region, s.get("StackId") or s["StackName"], s["StackName"], s.get("StackId"), status=s.get("StackStatus"), config=s)
            for page in client.get_paginator("list_stacks").paginate() for s in page.get("StackSummaries", [])
            if s.get("StackStatus") != "DELETE_COMPLETE"
        ])

    def _collect_messaging(self, region: str) -> list[Resource]:
        result: list[Resource] = []
        sqs = self.session.client("sqs", region_name=region)
        result += self._safe("SQS queues", lambda: [
            self._resource("AWS::SQS::Queue", region, url.rsplit("/", 1)[-1], url.rsplit("/", 1)[-1], url)
            for page in sqs.get_paginator("list_queues").paginate() for url in page.get("QueueUrls", [])
        ])
        sns = self.session.client("sns", region_name=region)
        result += self._safe("SNS topics", lambda: [
            self._resource("AWS::SNS::Topic", region, topic["TopicArn"].rsplit(":", 1)[-1], topic["TopicArn"].rsplit(":", 1)[-1], topic["TopicArn"])
            for page in sns.get_paginator("list_topics").paginate() for topic in page.get("Topics", [])
        ])
        return result

    def _collect_platform(self, region: str) -> list[Resource]:
        result: list[Resource] = []
        definitions = [
            ("apigateway", "get_rest_apis", "AWS::ApiGateway::RestApi", "items", "id", "name"),
            ("stepfunctions", "list_state_machines", "AWS::StepFunctions::StateMachine", "stateMachines", "name", "name"),
            ("ecr", "describe_repositories", "AWS::ECR::Repository", "repositories", "repositoryName", "repositoryName"),
            ("elasticache", "describe_cache_clusters", "AWS::ElastiCache::CacheCluster", "CacheClusters", "CacheClusterId", "CacheClusterId"),
            ("opensearch", "list_domain_names", "AWS::OpenSearchService::Domain", "DomainNames", "DomainName", "DomainName"),
            ("logs", "describe_log_groups", "AWS::Logs::LogGroup", "logGroups", "logGroupName", "logGroupName"),
            ("backup", "list_backup_vaults", "AWS::Backup::BackupVault", "BackupVaultList", "BackupVaultName", "BackupVaultName"),
        ]
        for service, method, resource_type, response_key, id_key, name_key in definitions:
            result += self._safe(f"{service} resources", lambda service=service, method=method, resource_type=resource_type, response_key=response_key, id_key=id_key, name_key=name_key: [
                self._resource(resource_type, region, str(item[id_key]), item.get(name_key), item.get("arn") or item.get("repositoryArn") or item.get("logGroupArn"), config=item)
                for page in ([self.session.client(service, region_name=region).list_domain_names()] if service == "opensearch" else self.session.client(service, region_name=region).get_paginator(method).paginate())
                for item in page.get(response_key, []) if item.get(id_key)
            ])
        return result

    def _collect_global(self) -> list[Resource]:
        result: list[Resource] = []
        s3 = self.session.client("s3", region_name=self.session.region_name or "us-east-1")
        result += self._safe("S3 buckets", lambda: [
            self._resource("AWS::S3::Bucket", "global", b["Name"], b["Name"], f"arn:aws:s3:::{b['Name']}", config=b)
            for b in s3.list_buckets().get("Buckets", [])
        ])
        route53 = self.session.client("route53", region_name=self.session.region_name or "us-east-1")
        result += self._safe("Route 53 hosted zones", lambda: [
            self._resource("AWS::Route53::HostedZone", "global", z["Id"].rsplit("/", 1)[-1], z.get("Name"), config=z)
            for page in route53.get_paginator("list_hosted_zones").paginate() for z in page.get("HostedZones", [])
        ])
        iam = self.session.client("iam", region_name=self.session.region_name or "us-east-1")
        for resource_type, method, key, name_key in [("AWS::IAM::Role", "list_roles", "Roles", "RoleName"), ("AWS::IAM::User", "list_users", "Users", "UserName"), ("AWS::IAM::Policy", "list_policies", "Policies", "PolicyName")]:
            result += self._safe(resource_type, lambda resource_type=resource_type, method=method, key=key, name_key=name_key: [
                self._resource(resource_type, "global", item.get("Arn") or item[name_key], item.get(name_key), item.get("Arn"), config=item)
                for page in (iam.get_paginator(method).paginate(Scope="Local") if method == "list_policies" else iam.get_paginator(method).paginate())
                for item in page.get(key, [])
            ])
        # CloudFront and CloudFront-scoped WAF are global APIs, exposed from
        # us-east-1 regardless of the account's default region.
        cloudfront = self.session.client("cloudfront", region_name="us-east-1")
        result += self._safe("CloudFront distributions", lambda: [
            self._resource("AWS::CloudFront::Distribution", "global", d.get("Id"), d.get("Comment") or d.get("DomainName"),
                           d.get("ARN"), config=d, status=d.get("Status"))
            for page in cloudfront.get_paginator("list_distributions").paginate()
            for d in (page.get("DistributionList") or {}).get("Items", [])
        ])
        waf = self.session.client("wafv2", region_name="us-east-1")
        result += self._safe("wafv2 cloudfront resources", lambda: [
            self._resource("AWS::WAFv2::WebACL", "global", w["ARN"].rsplit("/", 1)[-1], w.get("Name"), w.get("ARN"), config=w)
            for w in waf.list_web_acls(Scope="CLOUDFRONT").get("WebACLs", [])
        ])
        return result

    def _resource(self, resource_type: str, region: str, resource_id: str, name: Optional[str] = None,
                  arn: Optional[str] = None, tags: Optional[list[dict[str, Any]]] = None,
                  status: Optional[str] = None, config: Optional[dict[str, Any]] = None) -> Resource:
        return Resource(resource_type, self.account_id, region, str(resource_id), name, arn,
                        tuple(ResourceTag(str(t.get("Key")), str(t.get("Value", ""))) for t in (tags or []) if t.get("Key")),
                        config, status=status)

    @staticmethod
    def _tag_name(tags: Optional[list[dict[str, Any]]]) -> Optional[str]:
        return next((t.get("Value") for t in (tags or []) if t.get("Key") == "Name"), None)

    def _safe(self, label: str, operation) -> list[Resource]:
        try:
            result = operation()
            self.collection_status[label] = "Collected" if result else "No resources"
            return result
        except (ClientError, BotoCoreError) as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            self.collection_status[label] = "Denied" if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"} else "Unavailable"
            logger.warning("Skipping %s: %s", label, exc)
            return []
        except Exception as exc:
            self.collection_status[label] = "Unavailable"
            logger.warning("Skipping %s after unexpected error: %s", label, exc)
            return []
