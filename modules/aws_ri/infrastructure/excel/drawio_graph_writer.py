"""Readable, metadata-aware diagrams.net maps for AWS inventory reports."""

from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from aws_ri.domain.inventory.resource import Resource


PALETTES = {
    "Network": ("#d6eaff", "#5b9bd5"),
    "Compute": ("#e4d9ff", "#8064a2"),
    "Data": ("#d9f2d9", "#70ad47"),
    "Security": ("#f8d7da", "#c0504d"),
    "Other": ("#eeeeee", "#7f7f7f"),
}

RELATION_LABELS = {
    "NetworkInterfaceId": "Network interface",
    "SubnetIds": "Attached subnet",
    "LoadBalancerArns": "Load balancer",
    "TargetGroupArns": "Target group",
    "InstanceId": "EC2 instance",
    "SecurityGroupIds": "Security group",
    "SecurityGroups": "Security group",
    "VpcSecurityGroupIds": "Security group",
    "Role": "IAM role",
    "Layers": "Lambda layer",
}

KNOWN_KINDS = {
    "AWS::EC2::VPC": "VPC",
    "AWS::EC2::Subnet": "Subnet",
    "AWS::EC2::Instance": "EC2 instance",
    "AWS::EC2::NetworkInterface": "Network interface",
    "AWS::EC2::SecurityGroup": "Security group",
    "AWS::EC2::NetworkAcl": "Network ACL",
    "AWS::EC2::RouteTable": "Route table",
    "AWS::EC2::EIP": "Elastic IP",
    "AWS::EC2::NatGateway": "NAT gateway",
    "AWS::EC2::InternetGateway": "Internet gateway",
    "AWS::EC2::VpcEndpoint": "VPC endpoint",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "Load balancer",
    "AWS::ElasticLoadBalancing::LoadBalancer": "Load balancer",
    "AWS::Lambda::Function": "Lambda function",
    "AWS::IAM::Role": "IAM role",
    "AWS::IAM::User": "IAM user",
    "AWS::IAM::Policy": "IAM policy",
    "AWS::S3::Bucket": "S3 bucket",
    "AWS::RDS::DBInstance": "RDS instance",
    "AWS::RDS::DBCluster": "RDS cluster",
    "AWS::DynamoDB::Table": "DynamoDB table",
    "AWS::ECS::Cluster": "ECS cluster",
    "AWS::ECS::Service": "ECS service",
    "AWS::EKS::Cluster": "EKS cluster",
    "AWS::EKS::Nodegroup": "EKS node group",
    "AWS::KMS::Key": "KMS key",
}


class DrawioGraphWriter:
    """Build a VPC/subnet map and a separate, readable association index."""

    @classmethod
    def write(
        cls,
        path: Path,
        resources: Iterable[Resource],
        graph_records: Iterable[tuple[Resource, str, Any, str]],
    ) -> None:
        data = cls._build_graph(resources, graph_records)
        root = ET.Element("mxfile", {"host": "app.diagrams.net"})
        cls._write_index(root, data)
        for index, vpc_key in enumerate(sorted(data["vpcs"], key=lambda k: cls._node_sort(data["nodes"][k])), start=1):
            cls._write_vpc_page(root, data, vpc_key, index)
        cls._write_account_page(root, data)
        cls._write_associations_page(root, data)
        path.parent.mkdir(parents=True, exist_ok=True)
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)

    @classmethod
    def _build_graph(cls, resources, graph_records):
        nodes: dict[tuple[str, str, str], dict[str, Any]] = {}
        resource_keys: dict[int, tuple[str, str, str]] = {}
        alias_scoped: dict[tuple[str, str, str], list[tuple[str, str, str]]] = defaultdict(list)
        alias_global: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

        for resource in resources:
            key = cls._resource_key(resource)
            resource_keys[id(resource)] = key
            node = cls._resource_node(key, resource)
            nodes[key] = node
            aliases = {resource.resource_id, resource.arn, resource.resource_name, node["name"]}
            aliases.update(tag.value for tag in resource.tags if tag.key.lower() == "name")
            for alias in aliases:
                if not alias:
                    continue
                value = str(alias).strip()
                alias_scoped[(resource.account_id, resource.region, value)].append(key)
                alias_global[value].append(key)

        def add_reference(raw: Any, source: Resource) -> tuple[str, str, str] | None:
            if isinstance(raw, dict):
                raw = raw.get("Id") or raw.get("Arn") or raw.get("Name") or raw.get("id") or raw.get("arn") or raw.get("name")
            if raw in (None, "", [], {}):
                return None
            value = str(raw).strip()
            local = alias_scoped.get((source.account_id, source.region, value), [])
            matches = list(dict.fromkeys(local))
            if len(matches) == 1:
                return matches[0]
            global_matches = list(dict.fromkeys(alias_global.get(value, [])))
            if len(global_matches) == 1:
                return global_matches[0]
            if not cls._looks_like_resource_id(value):
                return None
            key = ("reference", source.account_id, f"{source.region}:{value}")
            if key not in nodes:
                kind = cls._kind_from_id(value)
                nodes[key] = {
                    "key": key,
                    "resource": None,
                    "account": source.account_id,
                    "region": source.region,
                    "id": value,
                    "name": "",
                    "kind": kind,
                    "category": cls._category(kind),
                    "virtual": True,
                }
                alias_scoped[(source.account_id, source.region, value)].append(key)
            return key

        edges = []
        edge_seen = set()
        for source, relation, raw_target, _group in graph_records:
            source_key = resource_keys.get(id(source))
            if source_key is None:
                continue
            target_key = add_reference(raw_target, source)
            raw_label = cls._reference_label(raw_target)
            relation = str(relation)
            if target_key == source_key:
                continue
            dedupe_key = (source_key, relation, target_key or raw_label)
            if dedupe_key in edge_seen:
                continue
            edge_seen.add(dedupe_key)
            edges.append({"source": source_key, "target": target_key, "target_label": raw_label, "relation": relation})

        vpcs = {key for key, node in nodes.items() if node["kind"] == "VPC"}
        subnets = {key for key, node in nodes.items() if node["kind"] == "Subnet"}
        subnet_vpc: dict[tuple[str, str, str], tuple[str, str, str]] = {}
        subnet_owners: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
        vpc_owners: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)

        for edge in edges:
            source, target, relation = edge["source"], edge["target"], edge["relation"]
            if target not in nodes:
                continue
            if relation.lower() == "vpcid" and target in vpcs:
                if source in subnets:
                    subnet_vpc[source] = target
                elif source != target:
                    vpc_owners[source].add(target)
            elif relation.lower() in {"subnetid", "subnetids"} and target in subnets:
                subnet_owners[source].add(target)

        # Configuration fields are a second source for AWS resources whose
        # relationship enrichment omitted VPC/Subnet links.
        for key, node in list(nodes.items()):
            resource = node["resource"]
            if resource is None:
                continue
            config = resource.configuration or {}
            for value in cls._configuration_values(config, {"vpcid"}):
                target = add_reference(value, resource)
                if target in nodes and nodes[target]["kind"] == "VPC":
                    vpcs.add(target)
                if target in vpcs and key not in vpcs:
                    if key in subnets:
                        subnet_vpc[key] = target
                    else:
                        vpc_owners[key].add(target)
            for value in cls._configuration_values(config, {"subnetid", "subnetids", "subnets"}):
                target = add_reference(value, resource)
                if target in nodes and nodes[target]["kind"] == "Subnet":
                    subnets.add(target)
                if target in subnets:
                    subnet_owners[key].add(target)

        for resource_key, owners in subnet_owners.items():
            direct_vpcs = vpc_owners.get(resource_key, set())
            if len(direct_vpcs) == 1:
                for subnet in owners:
                    subnet_vpc.setdefault(subnet, next(iter(direct_vpcs)))

        # Keep subnet records that lack a parent VPC visible under an explicit
        # unknown boundary instead of dropping them from the map.
        for subnet in subnets:
            if subnet in subnet_vpc:
                continue
            subnet_node = nodes[subnet]
            account, region = subnet_node["account"], subnet_node["region"]
            unknown_key = ("boundary", account, f"{region}:unresolved-vpc")
            if unknown_key not in nodes:
                nodes[unknown_key] = {
                    "key": unknown_key, "resource": None, "account": account,
                    "region": region, "id": "VPC not identified", "name": "",
                    "kind": "VPC", "category": "Network", "virtual": True,
                }
                vpcs.add(unknown_key)
            subnet_vpc[subnet] = unknown_key

        for resource_key, owners in subnet_owners.items():
            for subnet in owners:
                if subnet in subnet_vpc:
                    vpc_owners[resource_key].add(subnet_vpc[subnet])

        node_vpcs = {key: set(owners) for key, owners in vpc_owners.items()}
        for subnet, owner in subnet_vpc.items():
            node_vpcs.setdefault(subnet, set()).add(owner)
        for resource_key, owners in subnet_owners.items():
            for subnet in owners:
                if subnet in subnet_vpc:
                    node_vpcs.setdefault(resource_key, set()).add(subnet_vpc[subnet])

        # Multi-subnet resources are kept at VPC scope; the association table
        # retains the individual subnet links.
        subnet_members: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
        vpc_members: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
        account_members = set()
        resource_keys_all = {key for key, node in nodes.items() if node["resource"] is not None and key not in vpcs and key not in subnets}
        for key in resource_keys_all:
            owners = subnet_owners.get(key, set())
            if len(owners) == 1:
                subnet = next(iter(owners))
                subnet_members[subnet].add(key)
                if subnet in subnet_vpc:
                    vpc_members[subnet_vpc[subnet]].add(key)
            elif owners:
                for owner in vpc_owners.get(key, set()):
                    vpc_members[owner].add(key)
            elif len(vpc_owners.get(key, set())) == 1:
                vpc_members[next(iter(vpc_owners[key]))].add(key)
            elif vpc_owners.get(key):
                for owner in vpc_owners[key]:
                    vpc_members[owner].add(key)
            else:
                account_members.add(key)

        return {
            "nodes": nodes,
            "edges": edges,
            "vpcs": vpcs,
            "subnets": subnets,
            "subnet_vpc": subnet_vpc,
            "subnet_members": subnet_members,
            "vpc_members": vpc_members,
            "node_vpcs": node_vpcs,
            "account_members": account_members,
            "resource_keys": resource_keys_all,
        }

    @staticmethod
    def _resource_key(resource: Resource):
        return (resource.account_id, resource.region, resource.arn or f"{resource.resource_type}:{resource.resource_id}")

    @classmethod
    def _resource_node(cls, key, resource: Resource):
        tag_name = next((tag.value for tag in resource.tags if tag.key.lower() == "name" and tag.value), "")
        name = tag_name or resource.resource_name or ""
        if name == resource.resource_id:
            name = ""
        kind = KNOWN_KINDS.get(resource.resource_type)
        if not kind:
            short = resource.resource_type.split("::")[-1].replace("_", " ")
            kind = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", short).strip() or "AWS resource"
        return {
            "key": key,
            "resource": resource,
            "account": resource.account_id,
            "region": resource.region or "Unknown region",
            "id": resource.resource_id or resource.arn or "",
            "name": name,
            "kind": kind,
            "category": cls._category(resource.resource_type),
            "virtual": False,
        }

    @staticmethod
    def _category(resource_type: str) -> str:
        value = str(resource_type).lower()
        groups = {
            "Network": ("vpc", "subnet", "networkinterface", "network interface", "networkacl", "network acl", "routetable", "route table", "natgateway", "nat gateway", "internetgateway", "internet gateway", "vpcendpoint", "vpc endpoint", "elasticloadbalancing", "load balancer", "securitygroup", "security group", "::ec2::eip", "elastic ip"),
            "Compute": ("::ec2::instance", "ec2 instance", "::lambda::", "lambda function", "::ecs::", "ecs service", "::eks::", "eks cluster", "autoscaling", "apprunner", "sagemaker", "batch"),
            "Data": ("::s3::", "::rds::", "dynamodb", "elasticache", "opensearch", "redshift", "kinesis", "::sqs::", "::sns::", "glue", "athena", "efs"),
            "Security": ("::iam::", "iam role", "iam policy", "iam user", "::kms::", "waf", "cloudtrail", "guardduty", "shield", "::acm::", "backup", "securityhub", "identitycenter", "config"),
        }
        for category, terms in groups.items():
            if any(term in value for term in terms):
                return category
        return "Other"

    @staticmethod
    def _looks_like_resource_id(value: str) -> bool:
        return value.startswith(("vpc-", "subnet-", "eni-", "sg-", "acl-", "rtb-", "eipalloc-", "vpce-", "i-", "igw-", "nat-", "arn:"))

    @staticmethod
    def _kind_from_id(value: str) -> str:
        prefixes = (
            ("vpc-", "VPC"), ("subnet-", "Subnet"), ("eni-", "Network interface"),
            ("sg-", "Security group"), ("acl-", "Network ACL"), ("rtb-", "Route table"),
            ("eipalloc-", "Elastic IP"), ("vpce-", "VPC endpoint"), ("i-", "EC2 instance"),
            ("igw-", "Internet gateway"), ("nat-", "NAT gateway"),
        )
        return next((kind for prefix, kind in prefixes if value.startswith(prefix)), "AWS resource reference")

    @staticmethod
    def _reference_label(value: Any) -> str:
        if isinstance(value, dict):
            value = value.get("Id") or value.get("Arn") or value.get("Name") or value.get("id") or value.get("arn") or value.get("name")
        return str(value).strip() if value not in (None, "", [], {}) else "Unresolved reference"

    @classmethod
    def _configuration_values(cls, value: Any, keys: set[str]):
        found = []
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in keys:
                    found.extend(cls._flatten_values(child))
                elif key != "inventory_enrichment":
                    found.extend(cls._configuration_values(child, keys))
        elif isinstance(value, list):
            for child in value:
                found.extend(cls._configuration_values(child, keys))
        return list(dict.fromkeys(found))

    @classmethod
    def _flatten_values(cls, value: Any):
        if isinstance(value, dict):
            for key in ("Id", "id", "Arn", "arn", "Name", "name", "SubnetId", "subnetId"):
                if value.get(key):
                    return [str(value[key])]
            return []
        if isinstance(value, (list, tuple, set)):
            return [item for child in value for item in cls._flatten_values(child)]
        return [str(value)] if value not in (None, "") else []

    @staticmethod
    def _node_sort(node):
        return (node["account"], node["region"], node["name"].casefold(), node["id"].casefold())

    @staticmethod
    def _vpc_label(node):
        return node["name"] or node["id"]

    @classmethod
    def _display(cls, node):
        return node["name"] or node["id"] or node["kind"]

    @classmethod
    def _html_label(cls, node, head_size=11, detail_size=9):
        head = html.escape(node["kind"])
        name = html.escape(cls._display(node))
        if node["name"]:
            detail = html.escape(node["id"])
            return f'<div style="font-size:{head_size}px;font-weight:700">{head}: {name}</div><div style="font-size:{detail_size}px;color:#44546a">{detail}</div>'
        return f'<div style="font-size:{head_size}px;font-weight:700">{head}</div><div style="font-size:{detail_size}px;color:#44546a">{name}</div>'

    @classmethod
    def _new_page(cls, mxfile, name, width=2200, height=1400):
        diagram = ET.SubElement(mxfile, "diagram", {"name": name})
        model = ET.SubElement(diagram, "mxGraphModel", {
            "dx": str(width), "dy": str(height), "grid": "1", "page": "1",
            "pageScale": "1", "pageWidth": str(width), "pageHeight": str(height),
            "math": "0", "shadow": "0",
        })
        root = ET.SubElement(model, "root")
        ET.SubElement(root, "mxCell", {"id": "0"})
        ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
        return root

    @staticmethod
    def _shape(root, cell_id, value, x, y, width, height, style):
        cell = ET.SubElement(root, "mxCell", {"id": cell_id, "value": value, "style": style, "vertex": "1", "parent": "1"})
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(width), "height": str(height), "as": "geometry"})
        return cell

    @classmethod
    def _write_index(cls, mxfile, data):
        nodes = data["nodes"]
        vpcs = sorted(data["vpcs"], key=lambda key: cls._node_sort(nodes[key]))
        width, cols = 2100, 3
        card_w, card_h, gap_x, gap_y = 650, 126, 28, 18
        rows = (len(vpcs) + cols - 1) // cols
        height = 180 + max(1, rows) * (card_h + gap_y) + 150
        root = cls._new_page(mxfile, "Overview", width, height)
        cls._shape(root, "title", "AWS resource map", 36, 22, 1500, 44, "text;html=1;strokeColor=none;fillColor=none;fontColor=#172b4d;fontSize=26;align=left;verticalAlign=middle;")
        regions = sorted({n["region"] for n in nodes.values() if n["resource"] is not None})
        accounts = sorted({n["account"] for n in nodes.values() if n["resource"] is not None})
        resource_count = len(data["resource_keys"])
        relation_count = len(data["edges"])
        cls._shape(root, "subtitle", f"{len(accounts)} accounts  •  {len(regions)} regions  •  {len(vpcs)} VPCs  •  {len(data['subnets'])} subnets  •  {resource_count} resources  •  {relation_count} relationships", 38, 68, 1900, 24, "text;html=1;strokeColor=none;fillColor=none;fontColor=#52606d;fontSize=13;align=left;verticalAlign=middle;")
        for i, (category, (fill, stroke)) in enumerate(PALETTES.items()):
            cls._shape(root, f"legend-{i}", category, 40 + i * 142, 105, 126, 26, f"rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontColor=#000000;fontSize=11;")
        for idx, vpc_key in enumerate(vpcs):
            node = nodes[vpc_key]
            x = 40 + (idx % cols) * (card_w + gap_x)
            y = 150 + (idx // cols) * (card_h + gap_y)
            members = data["vpc_members"].get(vpc_key, set())
            subnet_count = sum(1 for subnet in data["subnets"] if data["subnet_vpc"].get(subnet) == vpc_key)
            counts = Counter(nodes[key]["category"] for key in members)
            summary = "   ".join(f"{category}: {counts[category]}" for category in PALETTES if counts[category])
            label = f'<div style="font-size:14px;font-weight:700">VPC: {html.escape(cls._vpc_label(node))}</div><div style="font-size:10px;color:#44546a">{html.escape(node["id"])}  •  {html.escape(node["region"])}  •  account {html.escape(node["account"])}</div><div style="font-size:11px;color:#52606d;margin-top:4px">{subnet_count} subnets  •  {len(members)} resources</div><div style="font-size:10px;color:#52606d">{html.escape(summary)}</div>'
            cls._shape(root, f"vpc-card-{idx}", label, x, y, card_w, card_h, "rounded=1;whiteSpace=wrap;html=1;fillColor=#f7f9fc;strokeColor=#91a4b7;fontColor=#000000;align=left;verticalAlign=middle;spacingLeft=16;spacingRight=10;")
        account_keys = sorted(data["account_members"], key=lambda key: cls._node_sort(nodes[key]))
        x = 40 + (len(vpcs) % cols) * (card_w + gap_x)
        y = 150 + (len(vpcs) // cols) * (card_h + gap_y)
        cls._shape(root, "account-card", f'<div style="font-size:14px;font-weight:700">Account and regional services</div><div style="font-size:11px;color:#52606d">{len(account_keys)} resources without a VPC placement</div>', x, y, card_w, card_h, "rounded=1;whiteSpace=wrap;html=1;fillColor=#f7f9fc;strokeColor=#91a4b7;fontColor=#000000;align=left;verticalAlign=middle;spacingLeft=16;")

    @classmethod
    def _write_vpc_page(cls, mxfile, data, vpc_key, page_index):
        nodes = data["nodes"]
        vpc = nodes[vpc_key]
        subnet_keys = sorted((key for key in data["subnets"] if data["subnet_vpc"].get(key) == vpc_key), key=lambda key: cls._node_sort(nodes[key]))
        members = set(data["vpc_members"].get(vpc_key, set()))
        subnet_union = set().union(*(data["subnet_members"].get(key, set()) for key in subnet_keys)) if subnet_keys else set()
        scope_nodes = sorted(members - subnet_union, key=lambda key: cls._node_sort(nodes[key]))
        subnet_cols, subnet_w, subnet_gap = 3, 660, 24
        grid_x, grid_y, node_cols = 48, 158, 3
        row_heights, subnet_groups = [], {}
        for row in range((len(subnet_keys) + subnet_cols - 1) // subnet_cols):
            heights = []
            for subnet_key in subnet_keys[row * subnet_cols:(row + 1) * subnet_cols]:
                group = sorted(data["subnet_members"].get(subnet_key, set()), key=lambda key: cls._node_sort(nodes[key]))
                subnet_groups[subnet_key] = group
                count_rows = max(1, (len(group) + node_cols - 1) // node_cols)
                heights.append(max(140, 68 + count_rows * 62))
            row_heights.append(max(heights, default=140))
        row_starts, running_y = [], grid_y
        for row_height in row_heights:
            row_starts.append(running_y)
            running_y += row_height + 30
        scope_cols = 6
        scope_rows = (len(scope_nodes) + scope_cols - 1) // scope_cols
        scope_height = 60 + scope_rows * 58 if scope_nodes else 0
        scope_y = running_y + 8 if scope_nodes else running_y
        bottom = scope_y + scope_height + 30
        width = 2200
        height = max(650, bottom + 50)
        title = f"VPC {cls._vpc_label(vpc)} · {vpc['region']}"
        root = cls._new_page(mxfile, title[:80], width, height)
        cls._shape(root, "title", f'<div style="font-size:20px;font-weight:700">VPC: {html.escape(cls._vpc_label(vpc))}</div><div style="font-size:12px;color:#52606d">{html.escape(vpc["id"])}  •  {html.escape(vpc["region"])}  •  account {html.escape(vpc["account"])}</div>', 36, 18, 1500, 54, "text;html=1;strokeColor=none;fillColor=none;fontColor=#172b4d;align=left;verticalAlign=middle;")
        cls._shape(root, "summary", f"{len(subnet_keys)} subnets  •  {len(members)} associated resources  •  resource-to-resource links are listed on Associations", 38, 78, 1800, 22, "text;html=1;strokeColor=none;fillColor=none;fontColor=#52606d;fontSize=11;align=left;verticalAlign=middle;")
        cls._shape(root, "vpc-boundary", f'VPC boundary  •  {html.escape(cls._vpc_label(vpc))}', 24, 112, width - 48, height - 136, "rounded=1;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#27ae9c;strokeWidth=2;fontColor=#172b4d;fontSize=15;verticalAlign=top;spacingTop=10;")
        node_index = 0
        for index, subnet_key in enumerate(subnet_keys):
            subnet = nodes[subnet_key]
            group = subnet_groups[subnet_key]
            count_rows = max(1, (len(group) + node_cols - 1) // node_cols)
            box_height = max(140, 68 + count_rows * 62)
            x = grid_x + (index % subnet_cols) * (subnet_w + subnet_gap)
            y = row_starts[index // subnet_cols]
            label = f'<div style="font-size:12px;font-weight:700">Subnet: {html.escape(cls._display(subnet))}</div><div style="font-size:9px;color:#44546a">{html.escape(subnet["id"])}  •  {html.escape(subnet["region"])}</div><div style="font-size:10px;color:#52606d">{len(group)} resources</div>'
            cls._shape(root, f"subnet-frame-{index}", label, x, y, subnet_w, box_height, "rounded=1;whiteSpace=wrap;html=1;fillColor=#f2f4f7;strokeColor=#8a9baa;strokeWidth=1;fontColor=#172b4d;align=left;verticalAlign=top;spacingTop=8;spacingLeft=12;")
            for item_index, key in enumerate(group):
                item = nodes[key]
                fill, stroke = PALETTES[item["category"]]
                nx = x + 14 + (item_index % node_cols) * 210
                ny = y + 58 + (item_index // node_cols) * 62
                cls._shape(root, f"resource-{page_index}-{node_index}", cls._html_label(item), nx, ny, 194, 48, f"rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontColor=#000000;fontSize=10;align=center;verticalAlign=middle;spacing=4;")
                node_index += 1
        if scope_nodes:
            cls._shape(root, "vpc-scope-frame", f"VPC-scoped resources  •  {len(scope_nodes)}", grid_x, scope_y, width - 96, scope_height, "rounded=1;whiteSpace=wrap;html=1;fillColor=#fbfcfd;strokeColor=#8a9baa;strokeWidth=1;fontColor=#172b4d;fontSize=12;align=left;verticalAlign=top;spacingTop=8;spacingLeft=12;")
            for item_index, key in enumerate(scope_nodes):
                item = nodes[key]
                fill, stroke = PALETTES[item["category"]]
                nx = grid_x + 14 + (item_index % scope_cols) * 338
                ny = scope_y + 42 + (item_index // scope_cols) * 58
                cls._shape(root, f"resource-{page_index}-{node_index}", cls._html_label(item), nx, ny, 320, 46, f"rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontColor=#000000;fontSize=10;align=center;verticalAlign=middle;spacing=4;")
                node_index += 1

    @classmethod
    def _write_account_page(cls, mxfile, data):
        nodes = data["nodes"]
        keys = sorted(data["account_members"], key=lambda key: (nodes[key]["account"], nodes[key]["region"], nodes[key]["category"], cls._node_sort(nodes[key])))
        cols, card_w, card_h, gap_x, gap_y = 5, 320, 58, 16, 16
        rows = (len(keys) + cols - 1) // cols
        root = cls._new_page(mxfile, "Account services", 1750, max(700, 130 + rows * (card_h + gap_y)))
        cls._shape(root, "title", "Account and regional services", 36, 20, 1100, 42, "text;html=1;strokeColor=none;fillColor=none;fontColor=#172b4d;fontSize=23;align=left;verticalAlign=middle;")
        cls._shape(root, "subtitle", f"{len(keys)} resources without an unambiguous VPC placement", 38, 64, 1200, 24, "text;html=1;strokeColor=none;fillColor=none;fontColor=#52606d;fontSize=12;align=left;verticalAlign=middle;")
        for index, key in enumerate(keys):
            node = nodes[key]
            fill, stroke = PALETTES[node["category"]]
            x, y = 38 + (index % cols) * (card_w + gap_x), 112 + (index // cols) * (card_h + gap_y)
            label = cls._html_label(node, 11, 9) + f'<div style="font-size:8px;color:#52606d">{html.escape(node["account"])} / {html.escape(node["region"])}</div>'
            cls._shape(root, f"account-resource-{index}", label, x, y, card_w, card_h, f"rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontColor=#000000;fontSize=10;align=center;verticalAlign=middle;spacing=4;")

    @classmethod
    def _write_associations_page(cls, mxfile, data):
        nodes = data["nodes"]
        edges = [edge for edge in data["edges"] if edge["relation"].lower() not in {"vpcid", "subnetid"}]
        edges.sort(key=lambda edge: (
            nodes[edge["source"]]["account"], nodes[edge["source"]]["region"],
            edge["relation"], cls._node_sort(nodes[edge["source"]]),
            cls._node_sort(nodes[edge["target"]]) if edge["target"] in nodes else (edge["target_label"],),
        ))
        row_height, top = 30, 146
        width = 1900
        root = cls._new_page(mxfile, "Associations", width, max(500, top + len(edges) * row_height + 40))
        cls._shape(root, "title", "Resource associations", 36, 20, 1100, 42, "text;html=1;strokeColor=none;fillColor=none;fontColor=#172b4d;fontSize=23;align=left;verticalAlign=middle;")
        cls._shape(root, "subtitle", f"{len(edges)} resource links. VPC and subnet placement appears as containment on the VPC tabs.", 38, 64, 1750, 24, "text;html=1;strokeColor=none;fillColor=none;fontColor=#52606d;fontSize=12;align=left;verticalAlign=middle;")
        xs, widths = (40, 460, 1060, 1365), (410, 590, 300, 495)
        for index, (x, cell_width, label) in enumerate(zip(xs, widths, ("Account / VPC", "From resource", "Relationship", "To resource"))):
            cls._shape(root, f"header-{index}", label, x, 108, cell_width, 38, "rounded=0;whiteSpace=wrap;html=1;fillColor=#e9eef4;strokeColor=#9aa8b5;fontColor=#172b4d;fontSize=12;fontStyle=1;align=left;verticalAlign=middle;spacingLeft=8;")
        for row, edge in enumerate(edges):
            source, target = nodes[edge["source"]], nodes.get(edge["target"])
            owner_vpcs = data["node_vpcs"].get(edge["source"], set()) | (data["node_vpcs"].get(edge["target"], set()) if target else set())
            vpc_key = min(owner_vpcs, key=lambda key: cls._node_sort(nodes[key])) if owner_vpcs else None
            if vpc_key:
                vpc_node = nodes[vpc_key]
                vpc_label = f"{cls._vpc_label(vpc_node)} · {vpc_node['region']} · {vpc_node['account']}"
            else:
                vpc_label = f"{source['account']} / {source['region']}"
            values = (
                vpc_label,
                cls._association_label(source),
                RELATION_LABELS.get(edge["relation"], edge["relation"]),
                cls._association_label(target) if target else edge["target_label"],
            )
            y, fill = top + row * row_height, "#ffffff" if row % 2 == 0 else "#f6f8fa"
            for col, (x, cell_width, value) in enumerate(zip(xs, widths, values)):
                cls._shape(root, f"row-{row}-{col}", html.escape(str(value)), x, y, cell_width, row_height, f"rectangle;whiteSpace=wrap;html=1;fillColor={fill};strokeColor=#d6dde5;fontColor=#000000;fontSize=10;align=left;verticalAlign=middle;spacingLeft=8;")

    @classmethod
    def _association_label(cls, node):
        if not node:
            return "Unresolved reference"
        return f"{node['kind']} · {node['name'] or node['id']}"
