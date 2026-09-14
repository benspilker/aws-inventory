"""CLI entry point for aws-ri."""

import logging
import os
import re
import stat
import sys
from dataclasses import replace
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Optional

import boto3
import click
import yaml

from aws_ri import __version__

from aws_ri.application.use_cases.generate_report import (
    GenerateReportUseCase,
    GenerateReportInput,
)
from aws_ri.infrastructure.aws.organizations_adapter import OrganizationsAdapter
from aws_ri.infrastructure.aws.config_adapter import (
    ConfigInventoryAdapter,
    ConfigPostureAdapter,
)
from aws_ri.infrastructure.aws.cost_explorer_adapter import CostExplorerAdapter
from aws_ri.infrastructure.aws.cur_cost_adapter import CurCostAdapter
from aws_ri.infrastructure.aws.trusted_advisor_adapter import TrustedAdvisorAdapter
from aws_ri.infrastructure.aws.security_hub_adapter import SecurityHubAdapter
from aws_ri.infrastructure.aws.identity_center_adapter import IdentityCenterAdapter
from aws_ri.application.ports.exceptions import ApplicationError, ConfigurationError
from aws_ri.infrastructure.aws.org_policy_adapter import OrgPolicyAdapter
from aws_ri.infrastructure.aws.resource_explorer_adapter import ResourceExplorerInventoryAdapter
from aws_ri.infrastructure.aws.account_local_inventory_adapter import AccountLocalInventoryAdapter
from aws_ri.infrastructure.aws.account_posture_adapter import AccountPostureAdapter
from aws_ri.infrastructure.excel.excel_writer import ExcelReportWriter
from aws_ri.infrastructure.logging.logging_adapter import FileLoggingAdapter
from aws_ri.domain.report_model import ReportModel
from aws_ri.domain.cost.cost_record import CostSummary
from aws_ri.domain.posture.compliance import ComplianceSummary, AdvisorSummary
from aws_ri.domain.posture.securityhub import SecurityHubSummary
from aws_ri.domain.posture.identity_center import IdentityCenterSummary
from aws_ri.domain.org.policies import OrgPolicySummary
from aws_ri.domain.posture.account_posture import AccountPostureSummary

PROFILE_CAPABILITIES = {
    'organizations': 'organizations',
    'inventory': 'inventory',
    'costs': 'costs',
    'posture': 'posture',
    'advisor': 'advisor',
    'security_hub': 'security_hub',
    'identity_center': 'identity_center',
    'policies': 'policies',
}

SAFE_ENV_KEY = re.compile(r'^[A-Z0-9_]+$')
SAFE_ENV_VALUE = re.compile(r'^[A-Za-z0-9_.:/@+=,\\\- ]+$')


def _sanitize_env_value(raw: str) -> str:
    value = raw.strip().strip('"').strip("'")
    if not value:
        return value
    if not SAFE_ENV_VALUE.fullmatch(value):
        raise ConfigurationError("Environment variable values may contain only alphanumeric or safe punctuation characters")
    return value


def _resolve_user_path(path: Path) -> Path:
    """Resolve a user-supplied path and block directory traversal."""
    if any(part == '..' for part in path.parts if part not in ('', '.')):
        raise ConfigurationError(f"Path traversal is not allowed: {path}")
    return path.expanduser().resolve()


@lru_cache(maxsize=1)
def _available_regions() -> set[str]:
    session = boto3.session.Session()
    regions: set[str] = set()
    for service in ('ec2', 'config', 'organizations', 'sts'):
        try:
            regions.update(session.get_available_regions(service, partition_name='aws'))
        except Exception:
            continue
    return regions


def _validate_region(region: str) -> None:
    if not region:
        return
    valid = _available_regions()
    if valid and region not in valid:
        raise ConfigurationError(f"Invalid AWS region '{region}'. Allowed regions: {', '.join(sorted(valid))}")


def _validate_regions(regions: Optional[list[str]]) -> Optional[list[str]]:
    if not regions:
        return None
    validated: list[str] = []
    for region in regions:
        _validate_region(region)
        validated.append(region)
    return validated


def _mask_account_id(account_id: Optional[str]) -> str:
    if not account_id:
        return 'unknown'
    if len(account_id) <= 4:
        return '*' * len(account_id)
    return f"{account_id[:2]}******{account_id[-2:]}"


def _mask_arn(arn: Optional[str]) -> str:
    if not arn:
        return 'unknown'
    parts = arn.split(':')
    if len(parts) < 6:
        return 'arn:***'
    resource = parts[-1]
    masked_resource = resource[:3] + '...' if len(resource) > 6 else resource
    return ':'.join(parts[:4] + ['***', masked_resource])


class SessionFactory:
    """Create boto3 sessions per capability, honoring delegated profiles."""

    def __init__(
        self,
        base_session_kwargs: dict,
        profile_mapping: dict[str, Optional[str]],
        credential_mapping: dict[str, dict],
    ) -> None:
        self.base_session_kwargs = base_session_kwargs
        self.profile_mapping = profile_mapping
        self.credential_mapping = credential_mapping
        self._cache: dict[str, boto3.Session] = {}

    def get(self, capability: str) -> boto3.Session:
        cred_config = self.credential_mapping.get(capability)
        if cred_config:
            cache_key = f"cred::{capability}"
            if cache_key not in self._cache:
                self._cache[cache_key] = self._session_from_credentials(cred_config)
            return self._cache[cache_key]

        profile = self.profile_mapping.get(capability)
        cache_key = profile or '__default__'
        if cache_key not in self._cache:
            session_kwargs = dict(self.base_session_kwargs)
            if profile:
                session_kwargs['profile_name'] = profile
            self._cache[cache_key] = boto3.Session(**session_kwargs)
        return self._cache[cache_key]

    def _session_from_credentials(self, config: dict) -> boto3.Session:
        env_values = {}
        env_file = config.get('env_file')
        if env_file:
            env_values = self._load_env_file(Path(env_file))

        access_key = config.get('access_key_id') or env_values.get('AWS_ACCESS_KEY_ID')
        secret_key = config.get('secret_access_key') or env_values.get('AWS_SECRET_ACCESS_KEY')
        session_token = config.get('session_token') or env_values.get('AWS_SESSION_TOKEN')
        region = config.get('region') or env_values.get('AWS_DEFAULT_REGION')

        if region:
            _validate_region(region)

        session_kwargs = dict(self.base_session_kwargs)
        if access_key and secret_key:
            session_kwargs['aws_access_key_id'] = access_key
            session_kwargs['aws_secret_access_key'] = secret_key
        if session_token:
            session_kwargs['aws_session_token'] = session_token
        if region:
            session_kwargs['region_name'] = region

        return boto3.Session(**session_kwargs)

    @staticmethod
    def _load_env_file(path: Path) -> dict[str, str]:
        values: dict[str, str] = {}
        safe_path = _resolve_user_path(path)
        if not safe_path.exists():
            return values
        if not safe_path.is_file():
            raise ConfigurationError(f"Env file {safe_path} must be a regular file")
        mode = stat.S_IMODE(safe_path.stat().st_mode)
        # On POSIX, reject group/other-readable credential files. Windows
        # exposes these bits as compatibility metadata rather than the NTFS
        # ACL, so this check would reject normal local files there.
        if os.name != 'nt' and mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ConfigurationError(f"Env file {safe_path} must not be accessible by group or others")
        with safe_path.open('r', encoding='utf-8') as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if '=' not in stripped:
                    continue
                key, val = stripped.split('=', 1)
                formatted_key = key.strip()
                for prefix in ('export ', 'set '):
                    if formatted_key.lower().startswith(prefix):
                        formatted_key = formatted_key[len(prefix):].strip()
                        break
                if not SAFE_ENV_KEY.fullmatch(formatted_key):
                    raise ConfigurationError(f"Invalid environment variable '{formatted_key}' in {safe_path}")
                values[formatted_key] = _sanitize_env_value(val)
        return values


def load_profile_mapping(
    default_profile: Optional[str],
    inline_overrides: dict[str, Optional[str]],
    base_mapping: Optional[dict[str, Optional[str]]] = None,
) -> dict[str, Optional[str]]:
    mapping: dict[str, Optional[str]] = dict(base_mapping or {})

    if default_profile:
        mapping.setdefault('organizations', default_profile)
        mapping.setdefault('inventory', default_profile)
        mapping.setdefault('posture', default_profile)
        mapping.setdefault('advisor', default_profile)
        mapping.setdefault('security_hub', default_profile)
        mapping.setdefault('costs', default_profile)
        mapping.setdefault('policies', default_profile)
        mapping.setdefault('identity_center', default_profile)

    for key, value in inline_overrides.items():
        if value:
            mapping[key] = value

    # Derived capability defaults: if a child capability is not explicitly
    # mapped, fall back to its parent domain so that five core entries cover
    # every bounded context.
    _apply_derived_defaults(mapping)
    return mapping


def load_credentials_mapping(
    base_mapping: Optional[dict[str, dict]] = None,
) -> dict[str, dict]:
    mapping: dict[str, dict] = dict(base_mapping or {})
    _apply_derived_defaults(mapping)
    return mapping


def load_access_config(
    access_path: Optional[Path],
) -> tuple[dict[str, Optional[str]], dict[str, dict], dict[str, dict]]:
    profile_mapping: dict[str, Optional[str]] = {}
    credential_mapping: dict[str, dict] = {}
    options: dict[str, dict] = {}

    if not access_path:
        return profile_mapping, credential_mapping, options

    expanded = _resolve_user_path(access_path)
    if not expanded.exists():
        return profile_mapping, credential_mapping, options

    with expanded.open('r', encoding='utf-8') as handle:
        data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ConfigurationError("Access config must be a mapping of capability -> settings")

        for capability, config in data.items():
            if capability not in PROFILE_CAPABILITIES:
                continue
            if isinstance(config, str):
                profile_mapping[capability] = config
            elif isinstance(config, dict):
                profile_value = config.get('profile')
                if profile_value:
                    profile_mapping[capability] = profile_value
                cred_values = {}
                for key in ('access_key_id', 'secret_access_key', 'session_token', 'region', 'env_file'):
                    if config.get(key):
                        if key == 'env_file':
                            env_path = Path(config[key])
                            if not env_path.is_absolute():
                                env_path = expanded.parent / env_path
                            cred_values[key] = str(_resolve_user_path(env_path))
                        else:
                            cred_values[key] = config.get(key)
                if cred_values:
                    credential_mapping[capability] = cred_values
                # Capture arbitrary options (currently only resource explorer view)
                extra = {}
                if capability == 'inventory' and config.get('resource_explorer_view'):
                    extra['resource_explorer_view'] = config.get('resource_explorer_view')
                if extra:
                    options.setdefault(capability, {}).update(extra)
            else:
                raise ConfigurationError(
                    f"Access config for '{capability}' must be a string profile name or mapping"
                )

    return profile_mapping, credential_mapping, options


def _apply_derived_defaults(mapping: dict) -> None:
    derived = {
        'policies': 'organizations',
        'advisor': 'organizations',
        'security_hub': 'posture',
    }
    for child, parent in derived.items():
        if child not in mapping and parent in mapping:
            mapping[child] = mapping[parent]

    org_profile = mapping.get('organizations')
    if org_profile:
        for capability in PROFILE_CAPABILITIES:
            mapping.setdefault(capability, org_profile)


# Configure logging
def setup_logging(verbose: bool) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )


@click.group()
@click.version_option(version=__version__, prog_name='aws-ri')
def cli():
    """AWS Resource Inventory - Generate comprehensive AWS organization reports."""
    pass


@cli.command()
@click.option(
    '--out',
    type=click.Path(path_type=Path),
    help='Output file path (default: AWS_Resource_Inventory_Report_YYYY-MM-DD_HH_mm.xlsx)',
)
@click.option(
    '--days',
    type=int,
    default=30,
    help='Time window for cost data in days (default: 30)',
)
@click.option(
    '--regions',
    type=str,
    help='Comma-separated list of regions to include (default: all)',
)
@click.option(
    '--aggregator-name',
    type=str,
    help='AWS Config Aggregator name (default: auto-detect)',
)
@click.option(
    '--resource-explorer-view',
    type=str,
    help='Optional Resource Explorer view name or ARN for inventory',
)
@click.option(
    '--no-costs',
    is_flag=True,
    help='Skip cost collection',
)
@click.option(
    '--no-posture',
    is_flag=True,
    help='Skip security posture collection',
)
@click.option(
    '--no-inventory',
    is_flag=True,
    help='Skip resource inventory collection',
)
@click.option(
    '--account-local-fallback',
    is_flag=True,
    help='Try Organizations first, then inventory the current account if organization access is denied',
)
@click.option(
    '--account-name',
    type=str,
    help='Account name to place in the report when using account-local fallback',
)
@click.option(
    '--lite',
    is_flag=True,
    help='Lite mode: skip charts and formatting for faster generation',
)
@click.option(
    '--profile',
    type=str,
    help='AWS profile name to use',
)
@click.option(
    '--access-config',
    type=click.Path(path_type=Path),
    default=None,
    help='Single YAML file describing per-capability profiles or credentials',
)
@click.option(
    '--env-file',
    type=click.Path(path_type=Path),
    default=None,
    help='Credential environment file containing AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and optional AWS_SESSION_TOKEN',
)
@click.option('--cur-database', type=str, help='Optional Athena database containing the AWS Cost and Usage Report')
@click.option('--cur-table', type=str, help='Optional Athena table containing the AWS Cost and Usage Report')
@click.option('--cur-workgroup', type=str, default='primary', show_default=True, help='Athena workgroup for CUR queries')
@click.option('--cur-output-location', type=str, help='Optional s3:// location for Athena query results')
@click.option('--organizations-profile', type=str, help='Profile override for AWS Organizations calls')
@click.option('--inventory-profile', type=str, help='Profile override for Config inventory')
@click.option('--cost-profile', type=str, help='Profile override for Cost Explorer')
@click.option('--posture-profile', type=str, help='Profile override for AWS Config compliance')
@click.option('--advisor-profile', type=str, help='Profile override for Trusted Advisor')
@click.option('--security-hub-profile', type=str, help='Profile override for Security Hub')
@click.option('--identity-center-profile', type=str, help='Profile override for IAM Identity Center data')
@click.option('--policies-profile', type=str, help='Profile override for organization policies')
@click.option(
    '--verbose',
    is_flag=True,
    help='Enable verbose logging',
)
@click.option(
    '--start-date',
    type=click.DateTime(formats=['%Y-%m-%d']),
    help='Optional cost window start date (YYYY-MM-DD)',
)
@click.option(
    '--end-date',
    type=click.DateTime(formats=['%Y-%m-%d']),
    help='Optional cost window end date (YYYY-MM-DD)',
)
@click.option(
    '--log-file',
    type=click.Path(path_type=Path),
    default=None,
    help='Optional custom log file path (defaults to logs/aws_ri_<timestamp>.log)',
)
def generate(
    out: Optional[Path],
    days: int,
    regions: Optional[str],
    aggregator_name: Optional[str],
    resource_explorer_view: Optional[str],
    no_costs: bool,
    no_posture: bool,
    no_inventory: bool,
    account_local_fallback: bool,
    account_name: Optional[str],
    lite: bool,
    profile: Optional[str],
    access_config: Optional[Path],
    env_file: Optional[Path],
    cur_database: Optional[str],
    cur_table: Optional[str],
    cur_workgroup: str,
    cur_output_location: Optional[str],
    organizations_profile: Optional[str],
    inventory_profile: Optional[str],
    cost_profile: Optional[str],
    posture_profile: Optional[str],
    advisor_profile: Optional[str],
    security_hub_profile: Optional[str],
    identity_center_profile: Optional[str],
    policies_profile: Optional[str],
    verbose: bool,
    start_date: Optional[datetime],
    end_date: Optional[datetime],
    log_file: Optional[Path],
    ):
    """Generate AWS Resource Inventory report.

    This command generates a comprehensive Excel report containing:
    - Organization account inventory
    - Resource inventory from AWS Config Aggregator
    - Cost analysis from Cost Explorer
    - Security posture from Config compliance and Trusted Advisor

    Examples:

        aws-ri generate

        aws-ri generate --out my-report.xlsx --days 60

        aws-ri generate --lite --no-posture

        aws-ri generate --regions us-east-1,us-west-2 --profile production
    """
    if days <= 0:
        raise click.ClickException("--days must be a positive integer")

    if start_date and end_date and end_date < start_date:
        raise click.ClickException("End date must be greater than or equal to start date")

    if log_file is None:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_dir = Path('logs')
        log_file = log_dir / f'aws_ri_{timestamp}.log'
    log_file = _resolve_user_path(log_file)

    setup_logging(verbose)
    FileLoggingAdapter(log_file).configure()
    logger = logging.getLogger(__name__)
    logger.info(f"Writing detailed logs to {log_file}")

    start_date_value = start_date.date() if start_date else None
    end_date_value = end_date.date() if end_date else None

    if no_inventory and no_costs and no_posture:
        raise click.ClickException("At least one of inventory, costs, or posture must be enabled")

    try:
        # Parse regions
        regions_list = None
        if regions:
            regions_list = [r.strip() for r in regions.split(',') if r.strip()]
            regions_list = _validate_regions(regions_list)

        safe_access_config = _resolve_user_path(access_config) if access_config else None
        access_profiles, access_credentials, access_options = load_access_config(safe_access_config)

        inventory_options = access_options.get('inventory', {})

        inline_overrides = {
            'organizations': organizations_profile,
            'inventory': inventory_profile,
            'costs': cost_profile,
            'posture': posture_profile,
            'advisor': advisor_profile,
            'security_hub': security_hub_profile,
            'identity_center': identity_center_profile,
            'policies': policies_profile,
        }

        profile_mapping = load_profile_mapping(
            default_profile=profile,
            inline_overrides=inline_overrides,
            base_mapping=access_profiles,
        )
        credential_mapping = load_credentials_mapping(
            base_mapping=access_credentials,
        )
        if env_file:
            resolved_env_file = _resolve_user_path(env_file)
            if not resolved_env_file.exists() or not resolved_env_file.is_file():
                raise ConfigurationError(f"Env file {resolved_env_file} must be an existing regular file")
            for capability in PROFILE_CAPABILITIES:
                credential_mapping.setdefault(capability, {})['env_file'] = str(resolved_env_file)
        resource_explorer_view = resource_explorer_view or inventory_options.get('resource_explorer_view')

        # Create session factory with delegated profile support
        session_kwargs = {}
        if profile:
            session_kwargs['profile_name'] = profile

        session_factory = SessionFactory(session_kwargs, profile_mapping, credential_mapping)

        # Verify credentials
        aws_account_id = None
        aws_principal_arn = None
        try:
            auth_session = session_factory.get('organizations')
            sts = auth_session.client('sts')
            identity = sts.get_caller_identity()
            aws_account_id = identity['Account']
            aws_principal_arn = identity['Arn']
            logger.info(f"Using AWS Account: {_mask_account_id(aws_account_id)}")
            logger.info(f"IAM Principal: {_mask_arn(aws_principal_arn)}")
        except Exception as e:
            logger.error("Failed to verify AWS credentials. Please configure AWS credentials.")
            logger.error(f"Error: {e}")
            sys.exit(1)

        # Wire dependencies (Dependency Injection)
        org_port = OrganizationsAdapter(session_factory.get('organizations'))
        inventory_session = session_factory.get('inventory')
        inventory_port = ConfigInventoryAdapter(inventory_session)
        account_local_inventory_port = AccountLocalInventoryAdapter(
            inventory_session,
            account_id=aws_account_id,
        )
        posture_regions = regions_list or sorted(account_local_inventory_port._enabled_regions())
        account_posture_port = AccountPostureAdapter(inventory_session, aws_account_id, posture_regions)
        resource_explorer_port = None
        if resource_explorer_view:
            resource_explorer_port = ResourceExplorerInventoryAdapter(inventory_session)
        if bool(cur_database) != bool(cur_table):
            raise ConfigurationError('--cur-database and --cur-table must be supplied together')
        cost_port = (CurCostAdapter(session_factory.get('costs'), cur_database, cur_table, cur_workgroup, cur_output_location)
                     if cur_database and cur_table else CostExplorerAdapter(session_factory.get('costs')))
        posture_port = ConfigPostureAdapter(session_factory.get('posture'))
        advisor_port = TrustedAdvisorAdapter(session_factory.get('advisor'))
        security_hub_port = SecurityHubAdapter(session_factory.get('security_hub'))
        identity_center_port = IdentityCenterAdapter(session_factory.get('identity_center'))
        policies_port = OrgPolicyAdapter(session_factory.get('policies'))
        report_writer = ExcelReportWriter()

        # Create use case
        use_case = GenerateReportUseCase(
            org_port=org_port,
            inventory_port=inventory_port,
            resource_explorer_port=resource_explorer_port,
            cost_port=cost_port,
            posture_port=posture_port,
            advisor_port=advisor_port,
            report_writer=report_writer,
            security_hub_port=security_hub_port,
            identity_center_port=identity_center_port,
            policies_port=policies_port,
            account_local_inventory_port=account_local_inventory_port,
            account_posture_port=account_posture_port,
        )

        # Prepare input
        input_params = GenerateReportInput(
            output_path=_resolve_user_path(out) if out else None,
            time_window_days=days,
            regions=regions_list,
            include_inventory=not no_inventory,
            include_costs=not no_costs,
            include_posture=not no_posture,
            lite_mode=lite,
            aggregator_name=aggregator_name,
            resource_explorer_view=resource_explorer_view,
            account_local_fallback=account_local_fallback,
            account_name=account_name,
            aws_account_id=aws_account_id,
            aws_principal_arn=aws_principal_arn,
            cost_start_date=start_date_value,
            cost_end_date=end_date_value,
        )

        # Execute use case
        click.echo("Starting AWS Resource Inventory report generation...")
        click.echo("")

        result = use_case.execute(input_params)

        # Display summary
        click.echo("")
        click.echo("Report generated successfully!")
        click.echo("")
        click.echo(f"Report location: {result.report_path}")
        click.echo("")
        click.echo("Summary:")
        click.echo(f"  - Accounts: {result.summary['total_accounts']}")
        click.echo(f"  - Resources: {result.summary['total_resources']}")
        click.echo(f"  - Tag Coverage: {result.summary['tag_coverage_pct']:.2f}%")

        if 'total_cost_usd' in result.summary:
            click.echo(f"  - Total Cost ({days} days): ${result.summary['total_cost_usd']:.2f}")

        if 'compliance_rate_pct' in result.summary:
            click.echo(f"  - Compliance Rate: {result.summary['compliance_rate_pct']:.2f}%")
            click.echo(f"  - Total Violations: {result.summary['total_violations']}")

        click.echo("")
        sys.exit(0)

    except ApplicationError as e:
        logger.error(f"Application error: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        click.echo("\nOperation cancelled by user", err=True)
        sys.exit(130)

    except Exception as e:
        logger.exception("Unexpected error occurred")
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


def _merge_multi_account_reports(reports: list[ReportModel]) -> ReportModel:
    """Merge independently authenticated account reports into one workbook model."""
    first = reports[0]
    accounts = tuple(account for report in reports for account in report.accounts.accounts)
    metadata = replace(
        first.metadata,
        included_regions=sorted({region for report in reports for region in report.metadata.included_regions}),
        aggregator_name='Multi-account account-local service APIs',
        aws_account_id='MULTI',
        aws_principal_arn='multiple principals',
    )
    compliance_rules = [rule for report in reports if report.compliance for rule in report.compliance.config_rules]
    advisor_findings = [finding for report in reports if report.advisor for finding in report.advisor.findings]
    security_findings = [finding for report in reports if report.security_hub for finding in report.security_hub.findings]
    posture_records = [record for report in reports if report.account_posture for record in report.account_posture.records]
    policies = {}
    for report in reports:
        if report.policies:
            for policy_type, values in report.policies.policies_by_type.items():
                policies.setdefault(policy_type, []).extend(values)
    collection_status = {}
    for report in reports:
        account_ids = sorted({account.id.value for account in report.accounts.accounts})
        prefix = account_ids[0] if len(account_ids) == 1 else 'account'
        collection_status.update({f'{prefix} / {label}': status for label, status in report.collection_status.items()})
    return ReportModel(
        metadata=metadata,
        accounts=type(first.accounts)(accounts=accounts),
        inventory=type(first.inventory)(resources=[resource for report in reports for resource in report.inventory.resources]),
        costs=CostSummary([record for report in reports if report.costs for record in report.costs.records]) if any(report.costs for report in reports) else None,
        compliance=ComplianceSummary(compliance_rules) if compliance_rules else None,
        advisor=AdvisorSummary(advisor_findings) if advisor_findings else None,
        security_hub=SecurityHubSummary(security_findings) if security_findings else None,
        identity_center=IdentityCenterSummary([instance for report in reports if report.identity_center for instance in report.identity_center.instances]) if any(report.identity_center for report in reports) else None,
        policies=OrgPolicySummary(policies) if policies else None,
        collection_status=collection_status,
        account_posture=AccountPostureSummary(posture_records) if posture_records else None,
    )


@cli.command(name='generate-multi')
@click.option('--accounts-file', type=click.Path(path_type=Path), required=True, help='YAML file containing accounts and per-account env_file paths')
@click.option('--out', type=click.Path(path_type=Path), required=True, help='Merged output workbook path')
@click.option('--days', type=int, default=30, show_default=True)
@click.option('--regions', type=str, help='Comma-separated regions; default is all enabled regions per account')
@click.option('--no-costs', is_flag=True)
@click.option('--no-posture', is_flag=True)
@click.option('--no-inventory', is_flag=True)
@click.option('--lite', is_flag=True, help='Skip charts and formatting')
def generate_multi(accounts_file: Path, out: Path, days: int, regions: Optional[str],
                   no_costs: bool, no_posture: bool, no_inventory: bool, lite: bool):
    """Scan multiple independently authenticated accounts into one report."""
    if days <= 0:
        raise click.ClickException('--days must be a positive integer')
    config_path = _resolve_user_path(accounts_file)
    if not config_path.exists():
        raise click.ClickException(f'Accounts file not found: {config_path}')
    payload = yaml.safe_load(config_path.read_text(encoding='utf-8')) or {}
    entries = payload.get('accounts') if isinstance(payload, dict) else payload
    if not isinstance(entries, list) or not entries:
        raise click.ClickException('Accounts file must contain a non-empty accounts list')
    regions_list = [value.strip() for value in regions.split(',') if value.strip()] if regions else None
    models: list[ReportModel] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get('env_file'):
            raise click.ClickException('Each account entry requires env_file and may include name/account_id')
        env_path = Path(entry['env_file'])
        if not env_path.is_absolute():
            env_path = config_path.parent / env_path
        env_path = _resolve_user_path(env_path)
        if not env_path.is_file():
            raise click.ClickException(f'Credential file not found: {env_path}')
        session = SessionFactory({}, {}, {'inventory': {'env_file': str(env_path)}}).get('inventory')
        identity = session.client('sts').get_caller_identity()
        actual_id = identity['Account']
        if entry.get('account_id') and str(entry['account_id']) != actual_id:
            raise click.ClickException(f'Credential account mismatch: expected {entry["account_id"]}, got {actual_id}')
        local = AccountLocalInventoryAdapter(session, actual_id)
        scan_regions = regions_list or sorted(local._enabled_regions())
        use_case = GenerateReportUseCase(
            org_port=OrganizationsAdapter(session),
            inventory_port=ConfigInventoryAdapter(session),
            resource_explorer_port=None,
            cost_port=CostExplorerAdapter(session),
            posture_port=ConfigPostureAdapter(session),
            advisor_port=TrustedAdvisorAdapter(session),
            report_writer=ExcelReportWriter(),
            security_hub_port=SecurityHubAdapter(session),
            identity_center_port=IdentityCenterAdapter(session),
            policies_port=OrgPolicyAdapter(session),
            account_local_inventory_port=local,
            account_posture_port=AccountPostureAdapter(session, actual_id, scan_regions),
        )
        result = use_case.execute(GenerateReportInput(
            output_path=out, time_window_days=days, regions=scan_regions,
            include_inventory=not no_inventory, include_costs=not no_costs,
            include_posture=not no_posture, lite_mode=lite,
            account_local_fallback=True, account_name=entry.get('name') or actual_id,
            aws_account_id=actual_id, aws_principal_arn=identity.get('Arn'), write_output=False,
        ))
        if result.report_model:
            models.append(result.report_model)
        click.echo(f'Completed account {actual_id}: {result.summary.get("total_resources", 0)} resources')
    merged = _merge_multi_account_reports(models)
    output_path = _resolve_user_path(out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ExcelReportWriter().write_report(merged, output_path)
    click.echo(f'Merged report generated: {output_path}')


def main():
    """Entry point for console script."""
    cli()


if __name__ == '__main__':
    main()
