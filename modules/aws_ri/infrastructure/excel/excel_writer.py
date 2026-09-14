"""Excel report writer implementation using xlsxwriter."""

import logging
import json
import xml.etree.ElementTree as ET
from collections import OrderedDict
from pathlib import Path
from decimal import Decimal
from typing import Any, Optional
from datetime import datetime

import xlsxwriter
from xlsxwriter.workbook import Workbook
from xlsxwriter.worksheet import Worksheet

from aws_ri.application.ports.report_port import ReportWriterPort
from aws_ri.application.ports.exceptions import ReportWriterError
from aws_ri.domain.report_model import ReportModel
from aws_ri.domain.posture.securityhub import SecurityHubSeverity
from aws_ri.domain.posture.compliance import AdvisorSeverity


logger = logging.getLogger(__name__)

MAX_ATTRIBUTE_COLUMNS = 10

# Chart size presets for consistent visual appearance
CHART_SIZE_STANDARD = {'width': 640, 'height': 380}
CHART_SIZE_PIE = {'width': 640, 'height': 360}
CHART_SIZE_HORIZONTAL_BAR = {'width': 640, 'height': 450}
CHART_SIZE_RISK = {'width': 680, 'height': 420}

# Plot area layouts for different chart types
PLOT_AREA_ROTATED_LABELS = {
    'x': 0.13,
    'y': 0.15,
    'width': 0.82,
    'height': 0.65,
}
PLOT_AREA_HORIZONTAL_BAR = {
    'x': 0.25,
    'y': 0.15,
    'width': 0.70,
    'height': 0.75,
}
PLOT_AREA_STANDARD = {
    'x': 0.15,
    'y': 0.2,
    'width': 0.75,
    'height': 0.7,
}


class ExcelReportWriter(ReportWriterPort):
    """Excel report writer using xlsxwriter.

    Generates comprehensive Excel workbook with multiple sheets:
    - Summary: Dashboard with KPIs and charts
    - Accounts: Account-level summary
    - Regions: Region-level summary
    - Resources: Detailed resource inventory
    - Costs: Cost breakdown
    - Posture: Security posture summary
    """

    def write_report(self, report: ReportModel, output_path: Path) -> None:
        """Write report to Excel file.

        Args:
            report: ReportModel containing all data.
            output_path: Path to output .xlsx file.

        Raises:
            ReportWriterError: If unable to write report.
        """
        try:
            logger.info(f"Creating Excel workbook at {output_path}")

            # AWS returns many timestamps as timezone-aware datetimes. Excel
            # stores dates without timezone metadata, so normalize them while
            # preserving the timestamp value for report readability.
            with xlsxwriter.Workbook(str(output_path), {'remove_timezone': True}) as workbook:
                # Define formats
                formats = self._create_formats(workbook)

                type_sheet_names = self._prepare_resource_type_sheet_names(report)

                # Prepare Summary + chart data sheets first so Summary stays first tab.
                summary_sheet = workbook.add_worksheet('Summary')
                chart_sheet = workbook.add_worksheet('Chart Data')
                chart_sheet.hide()

                # Write sheets
                self._write_summary_sheet(workbook, summary_sheet, chart_sheet, report, formats)

                if report.collection_status:
                    self._write_collection_status_sheet(workbook, report, formats)

                if report.has_costs():
                    self._write_costs_sheet(workbook, report, formats)

                if report.org_hierarchy:
                    self._write_organizational_units_sheet(workbook, report, formats)

                if report.policies:
                    self._write_policies_sheet(workbook, report, formats)

                self._write_accounts_sheet(workbook, report, formats)
                self._write_regions_sheet(workbook, report, formats)

                if report.compliance or report.advisor or report.identity_center or report.policies:
                    self._write_security_posture_sheet(workbook, report, formats)

                if report.compliance:
                    self._write_compliance_details_sheet(workbook, report, formats)
                if report.advisor:
                    self._write_trusted_advisor_details_sheet(workbook, report, formats)
                if report.security_hub:
                    self._write_security_hub_details_sheet(workbook, report, formats)
                if report.account_posture:
                    self._write_account_posture_sheet(workbook, report, formats)

                if report.identity_center:
                    self._write_identity_center_sheet(workbook, report, formats)

                if report.inventory.total_count() > 0:
                    tags_sheet = workbook.add_worksheet('Resource Tags')
                    type_summary_sheet = workbook.add_worksheet('Resource Types Summary')
                    graph_edges = self._extract_graph_edges(report)
                    if graph_edges:
                        self._write_relationship_graph_sheet(workbook, graph_edges, formats)
                    successfully_created = self._write_resource_type_sheets(
                        workbook,
                        report,
                        formats,
                        type_sheet_names,
                    )
                    self._write_resource_type_summary_sheet(
                        workbook,
                        report,
                        formats,
                        type_sheet_names,
                        successfully_created,
                        sheet=type_summary_sheet,
                    )
                    self._write_tags_sheet(workbook, report, formats, sheet=tags_sheet)

                # Debug: Log cost information
                if report.costs:
                    logger.info(f"Report has costs: {len(report.costs.records)} records, total ${report.costs.total_cost()}")
                else:
                    logger.warning("Report has no cost data")

            logger.info(f"Excel report written successfully to {output_path}")
            graph_edges = self._extract_graph_edges(report)
            if graph_edges:
                self._write_drawio_graph(output_path.with_suffix('.drawio'), graph_edges)

        except Exception as e:
            raise ReportWriterError(f"Failed to write Excel report: {e}") from e

    @staticmethod
    def _extract_graph_edges(report: ReportModel) -> list[tuple[str, str, str, str]]:
        """Normalize enrichment links into source/relationship/target rows."""
        edges: list[tuple[str, str, str, str]] = []
        for resource in report.inventory.resources:
            source = resource.arn or resource.resource_id
            enrichment = (resource.configuration or {}).get('inventory_enrichment', {})
            for group in ('relationships', 'dependencies'):
                for relation, raw in (enrichment.get(group) or {}).items():
                    values = raw if isinstance(raw, (list, tuple, set)) else [raw]
                    for value in values:
                        if isinstance(value, dict):
                            value = value.get('Id') or value.get('Arn') or value.get('Name')
                        if value not in (None, '', [], {}):
                            edges.append((str(source), str(relation), str(value), group))
        return list(dict.fromkeys(edges))

    def _write_relationship_graph_sheet(self, workbook: Workbook, edges, formats) -> None:
        sheet = workbook.add_worksheet('Relationship Graph')
        sheet.write(0, 0, 'Relationship Graph Index', formats['title'])
        sheet.write(1, 0, 'Open the adjacent .drawio file in diagrams.net for a visual graph.', formats['subtitle'])
        headers = ['Source', 'Relationship', 'Target', 'Relationship Class']
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])
        for row, edge in enumerate(edges, start=4):
            for col, value in enumerate(edge):
                sheet.write(row, col, value)
        sheet.autofilter(3, 0, max(3, len(edges) + 3), len(headers) - 1)
        sheet.freeze_panes(4, 0)
        sheet.set_column('A:A', 60)
        sheet.set_column('B:B', 24)
        sheet.set_column('C:C', 60)
        sheet.set_column('D:D', 22)

    @staticmethod
    def _write_drawio_graph(path: Path, edges) -> None:
        """Write an Azure-ARI-style multi-page diagrams.net XML graph."""
        mxfile = ET.Element('mxfile', {'host': 'app.diagrams.net'})
        categories = {
            'Network': ('vpc', 'subnet', 'securitygroup', 'security group', 'networkinterface', 'route', 'nat', 'internetgateway', 'eip'),
            'Compute': ('lambda', 'ec2', 'ecs', 'eks', 'emr', 'sagemaker', 'apprunner', 'beanstalk'),
            'Data': ('s3', 'rds', 'dynamodb', 'sqs', 'sns', 'kinesis', 'kafka', 'glue', 'athena', 'redshift', 'opensearch'),
            'Security': ('iam', 'waf', 'cloudtrail', 'guardduty', 'shield', 'acm', 'backup', 'policy', 'role'),
        }

        def category(edge):
            text = ' '.join(str(v).lower() for v in edge[:3])
            for name, terms in categories.items():
                if any(term in text for term in terms):
                    return name
            return 'Other'

        grouped = {name: [] for name in (*categories.keys(), 'Other')}
        for edge in edges:
            grouped[category(edge)].append(edge)

        # Overview aggregates many resource-level links into service-level links,
        # keeping the landing page readable while detail pages retain every edge.
        overview = {}
        for source, relation, target, _ in edges:
            source_service = ExcelReportWriter._graph_service_name(source)
            target_service = ExcelReportWriter._graph_service_name(target)
            key = (source_service, relation, target_service)
            overview[key] = overview.get(key, 0) + 1
        overview_edges = [(s, f'{rel} ({count})', t, 'summary') for (s, rel, t), count in overview.items()]
        pages = [('Overview', overview_edges)] + [(name, values) for name, values in grouped.items() if values]
        for page_name, page_edges in pages:
            diagram = ET.SubElement(mxfile, 'diagram', {'name': page_name})
            ExcelReportWriter._write_drawio_page(diagram, page_edges, page_name)
        ET.ElementTree(mxfile).write(path, encoding='utf-8', xml_declaration=True)

    @staticmethod
    def _graph_service_name(value: str) -> str:
        """Convert an ARN or identifier to a compact diagram label."""
        text = str(value)
        if text.startswith('arn:'):
            parts = text.split(':', 5)
            service = parts[2] if len(parts) > 2 else 'aws'
            resource = parts[5] if len(parts) > 5 else text
            return f'{service}: {resource.rsplit("/", 1)[-1].rsplit(":", 1)[-1][:48]}'
        return text[:56]

    @staticmethod
    def _write_drawio_page(diagram, edges, page_name: str) -> None:
        model = ET.SubElement(diagram, 'mxGraphModel', {'dx': '1400', 'dy': '900', 'grid': '1', 'page': '1', 'pageScale': '1'})
        root = ET.SubElement(model, 'root')
        ET.SubElement(root, 'mxCell', {'id': '0'})
        ET.SubElement(root, 'mxCell', {'id': '1', 'parent': '0'})
        nodes: dict[str, str] = {}
        for source, relation, target, _ in edges:
            for value in (source, target):
                if value in nodes:
                    continue
                node_id = f'n{len(nodes) + 1}'
                nodes[value] = node_id
                idx = len(nodes) - 1
                x, y = (idx % 5) * 280, (idx // 5) * 100
                label = ExcelReportWriter._graph_service_name(value) if page_name == 'Overview' else ExcelReportWriter._graph_display_name(value)
                fill, stroke = ExcelReportWriter._graph_colors(value, page_name)
                style = f'rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontColor=#000000;fontSize=11;'
                cell = ET.SubElement(root, 'mxCell', {'id': node_id, 'value': label, 'style': style, 'vertex': '1', 'parent': '1'})
                ET.SubElement(cell, 'mxGeometry', {'x': str(x), 'y': str(y), 'width': '250', 'height': '58', 'as': 'geometry'})
        for idx, (source, relation, target, _) in enumerate(edges, start=1):
            cell = ET.SubElement(root, 'mxCell', {'id': f'e{idx}', 'value': relation, 'style': 'edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;jettySize=auto;orthogonalLoop=1;', 'edge': '1', 'parent': '1', 'source': nodes[source], 'target': nodes[target]})
            ET.SubElement(cell, 'mxGeometry', {'relative': '1', 'as': 'geometry'})

    @staticmethod
    def _graph_display_name(value: str) -> str:
        """Use a compact node label; the full value remains in the Excel index."""
        text = str(value)
        if text.startswith('arn:'):
            parts = text.split(':', 5)
            service = parts[2] if len(parts) > 2 else 'aws'
            resource = parts[5] if len(parts) > 5 else text
            return f'{service}: {resource.rsplit("/", 1)[-1][:52]}'
        return text[:60]

    @staticmethod
    def _graph_colors(value: str, page_name: str) -> tuple[str, str]:
        """Return a readable fill/stroke pair for a graph node."""
        palettes = {
            'Network': ('#d6eaff', '#5b9bd5'),
            'Compute': ('#e4d9ff', '#8064a2'),
            'Data': ('#d9f2d9', '#70ad47'),
            'Security': ('#f8d7da', '#c0504d'),
            'Other': ('#eeeeee', '#7f7f7f'),
        }
        if page_name != 'Overview':
            return palettes.get(page_name, palettes['Other'])
        text = str(value).lower()
        groups = {
            'Network': ('ec2:', 'vpc-', 'subnet-', 'security', 'network', 'route', 'gateway', 'eip'),
            'Compute': ('lambda:', 'ecs:', 'eks:', 'sagemaker:', 'emr:', 'apprunner:', 'beanstalk:', 'instance/'),
            'Data': ('s3:', 'rds:', 'dynamodb:', 'sqs:', 'sns:', 'kinesis:', 'kafka:', 'glue:', 'athena:', 'redshift:', 'opensearch:'),
            'Security': ('iam:', 'waf:', 'cloudtrail:', 'guardduty:', 'shield:', 'acm:', 'backup:', 'role/'),
        }
        for group, terms in groups.items():
            if any(term in text for term in terms):
                return palettes[group]
        return palettes['Other']

    def _create_formats(self, workbook: Workbook) -> dict[str, Any]:
        """Create reusable cell formats."""
        return {
            'header': workbook.add_format({
                'bold': True,
                'bg_color': '#4472C4',
                'font_color': 'white',
                'border': 1,
                'align': 'center',
                'valign': 'vcenter',
            }),
            'title': workbook.add_format({
                'bold': True,
                'font_size': 16,
                'font_color': '#1F4E78',
            }),
            'subtitle': workbook.add_format({
                'bold': True,
                'font_size': 12,
                'font_color': '#4472C4',
            }),
            'currency': workbook.add_format({
                'num_format': '$#,##0.00',
            }),
            'percent': workbook.add_format({
                'num_format': '0.00%',
            }),
            'number': workbook.add_format({
                'num_format': '#,##0',
            }),
            'date': workbook.add_format({
                'num_format': 'yyyy-mm-dd hh:mm:ss',
            }),
            'good': workbook.add_format({
                'bg_color': '#C6EFCE',
                'font_color': '#006100',
            }),
            'warning': workbook.add_format({
                'bg_color': '#FFEB9C',
                'font_color': '#9C6500',
            }),
            'bad': workbook.add_format({
                'bg_color': '#FFC7CE',
                'font_color': '#9C0006',
            }),
            'panel_header': workbook.add_format({
                'bold': True,
                'font_color': 'white',
                'bg_color': '#1F4E78',
                'border': 1,
                'align': 'center',
                'valign': 'vcenter',
            }),
            'panel_subheader': workbook.add_format({
                'bold': True,
                'bg_color': '#D9E1F2',
                'border': 1,
            }),
            'panel_cell': workbook.add_format({
                'border': 1,
            }),
            'card_title': workbook.add_format({
                'bold': True,
                'font_color': 'white',
                'bg_color': '#305496',
                'align': 'center',
                'valign': 'vcenter',
                'border': 1,
            }),
            'card_value': workbook.add_format({
                'bold': True,
                'font_size': 16,
                'align': 'center',
                'valign': 'vcenter',
                'border': 1,
            }),
        }

    def _write_summary_sheet(
        self,
        workbook: Workbook,
        sheet: Worksheet,
        chart_sheet: Worksheet,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write Azure-inspired Summary dashboard."""
        sheet.set_column('A:A', 28)
        sheet.set_column('B:B', 10)
        sheet.set_column('C:C', 2)
        sheet.set_column('D:F', 22)
        sheet.set_column('G:G', 4)
        sheet.set_column('H:N', 16)
        sheet.hide_gridlines(2)

        self._write_reported_resources_panel(sheet, report, formats)
        self._write_metadata_panel(sheet, report, formats)
        self._write_summary_cards(sheet, report, formats)
        if not report.metadata.lite_mode:
            self._write_summary_charts(workbook, sheet, chart_sheet, report)

    def _write_collection_status_sheet(self, workbook: Workbook, report: ReportModel, formats: dict) -> None:
        """Write collection outcomes so denied services are not mistaken for empty services."""
        sheet = workbook.add_worksheet('Collection Status')
        sheet.hide_gridlines(2)
        sheet.write(0, 0, 'Collection Status', formats['title'])
        sheet.write(1, 0, 'Status reflects the authenticated role and account SCPs at scan time.', formats['subtitle'])
        headers = ['Service / Collector', 'Status']
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])
        row = 4
        for label, status in sorted(report.collection_status.items()):
            sheet.write(row, 0, label)
            style = {'Collected': formats['good'], 'No resources': formats['panel_cell'],
                     'Denied': formats['bad'], 'Unavailable': formats['warning']}.get(status, formats['panel_cell'])
            sheet.write(row, 1, status, style)
            row += 1
        if row > 4:
            sheet.autofilter(3, 0, row - 1, 1)
            sheet.freeze_panes(4, 0)
        sheet.set_column('A:A', 34)
        sheet.set_column('B:B', 18)

    def _write_account_posture_sheet(self, workbook: Workbook, report: ReportModel, formats: dict) -> None:
        """Write GuardDuty, Inspector, Macie, IAM and other account posture records."""
        sheet = workbook.add_worksheet('Account Posture')
        sheet.hide_gridlines(2)
        sheet.write(0, 0, 'Account Posture Details', formats['title'])
        sheet.write(1, 0, 'Read-only account and security-service posture collected for the authenticated account.', formats['subtitle'])
        headers = ['Category', 'Record ID', 'Status', 'Severity', 'Region', 'Resource', 'Title', 'Details']
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])
        row = 4
        for record in report.account_posture.records:
            values = [record.category, record.record_id, record.status, record.severity, record.region,
                      record.resource, record.title, json.dumps(record.details, default=str, separators=(',', ':'))]
            for col, value in enumerate(values):
                sheet.write(row, col, value)
            row += 1
        if row > 4:
            sheet.autofilter(3, 0, row - 1, len(headers) - 1)
            sheet.freeze_panes(4, 0)
        sheet.set_column('A:A', 24)
        sheet.set_column('B:B', 42)
        sheet.set_column('C:D', 16)
        sheet.set_column('E:E', 18)
        sheet.set_column('F:F', 48)
        sheet.set_column('G:G', 32)
        sheet.set_column('H:H', 90)

    def _write_reported_resources_panel(
        self,
        sheet: Worksheet,
        report: ReportModel,
        formats: dict,
    ) -> None:
        sheet.merge_range(0, 0, 0, 1, 'Top Resource Types (by count)', formats['panel_header'])
        sheet.write(1, 0, 'Name', formats['panel_subheader'])
        sheet.write(1, 1, 'Count', formats['panel_subheader'])

        counts = sorted(
            report.inventory.count_by_type().items(),
            key=lambda x: x[1],
            reverse=True,
        )
        for idx, (resource_type, count) in enumerate(counts[:50], start=2):
            sheet.write(idx, 0, resource_type, formats['panel_cell'])
            sheet.write(idx, 1, count, formats['panel_cell'])

    def _write_metadata_panel(
        self,
        sheet: Worksheet,
        report: ReportModel,
        formats: dict,
    ) -> None:
        start_col = 3
        sheet.merge_range(0, start_col, 0, start_col + 2, 'AWS Resource Inventory', formats['panel_header'])

        metadata_rows = [
            ('Version', f"aws-ri v{report.metadata.tool_version}"),
            ('Report Date', report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')),
            (
                'Time Window',
                (
                    f"{report.metadata.cost_start_date} to {report.metadata.cost_end_date}"
                    if report.metadata.cost_start_date and report.metadata.cost_end_date
                    else f"Last {report.metadata.time_window_days} days"
                ),
            ),
            ('Aggregator', report.metadata.aggregator_name or 'Auto-detected'),
            ('AWS Account', report.metadata.aws_account_id or 'Unknown'),
            ('AWS Principal', report.metadata.aws_principal_arn or 'Unknown'),
            ('Processing Time', self._format_duration(report.metadata.data_collection_seconds)),
            ('Reporting Time', self._format_duration(report.metadata.data_reporting_seconds)),
            ('Regions', ', '.join(report.metadata.included_regions) if report.metadata.included_regions else 'All regions'),
        ]

        row = 1
        for label, value in metadata_rows:
            sheet.write(row, start_col, label, formats['panel_subheader'])
            sheet.merge_range(row, start_col + 1, row, start_col + 2, value, formats['panel_cell'])
            row += 1

    def _write_summary_cards(
        self,
        sheet: Worksheet,
        report: ReportModel,
        formats: dict,
    ) -> None:
        def write_card(row_index: int, col_index: int, title: str, value: str) -> None:
            sheet.merge_range(row_index, col_index, row_index, col_index + 1, title, formats['card_title'])
            sheet.merge_range(row_index + 1, col_index, row_index + 2, col_index + 1, value, formats['card_value'])

        primary_rows = [
            [
                ('Total Resources', f"{report.inventory.total_count():,}"),
                ('Active Accounts', f"{len(report.accounts.active_accounts()):,}"),
                ('Total Accounts', f"{len(report.accounts):,}"),
            ],
            [
                ('Tag Coverage', f"{report.inventory.tag_coverage():.2f}%"),
                ('Regions with Resources', f"{len(report.inventory.count_by_region())}"),
                ('Has Costs', 'Yes' if report.has_costs() else 'No'),
            ],
        ]

        base_col = 7
        base_row = 1
        for r_idx, row in enumerate(primary_rows):
            for c_idx, (title, value) in enumerate(row):
                card_col = base_col + c_idx * 3
                card_row = base_row + r_idx * 4
                write_card(card_row, card_col, title, value)

        # Add third row with cost and security metrics (minimal additions)
        third_row = []
        if report.costs:
            total_cost = f"${report.costs.total_cost():,.2f}"
            third_row.append(('Total Cost', total_cost))

            top_service = report.costs.top_services(1)
            if top_service:
                third_row.append(('Top Cost Service', top_service[0][0]))

        if report.security_hub:
            findings_by_sev = report.security_hub.findings_by_severity()
            critical_high = findings_by_sev.get('CRITICAL', 0) + findings_by_sev.get('HIGH', 0)
            third_row.append(('Critical/High Findings', f"{critical_high:,}"))

        if third_row:
            for c_idx, (title, value) in enumerate(third_row):
                card_col = base_col + c_idx * 3
                card_row = base_row + 8  # Row 3 (after row 2 which ends at base_row + 7)
                write_card(card_row, card_col, title, value)

        if report.compliance:
            compliance_rate = f"{report.compliance.overall_compliance_rate():.2f}%"
            violations = f"{report.compliance.total_violations():,}"
            compliance_col = 16  # Column Q
            write_card(base_row, compliance_col, 'Compliance Rate', compliance_rate)
            write_card(base_row + 4, compliance_col, 'Total Violations', violations)

    def _write_summary_charts(
        self,
        workbook: Workbook,
        summary_sheet: Worksheet,
        data_sheet: Worksheet,
        report: ReportModel,
    ) -> None:
        chart_data_row = 40

        account_labels = self._account_labels(report)

        if report.costs:
            cost_by_account = sorted(
                (
                    (account_labels.get(acc, acc), float(cost))
                    for acc, cost in report.costs.cost_by_account().items()
                ),
                key=lambda x: x[1],
                reverse=True,
            )[:10]
            if cost_by_account:
                chart_row = self._write_chart_data(data_sheet, chart_data_row, cost_by_account)
                self._insert_column_chart(
                    workbook,
                    summary_sheet,
                    'H15',
                    'AWS Cost per Account',
                    data_sheet.get_name(),
                    chart_row,
                    len(cost_by_account),
                    x_axis_name='Account',
                    y_axis_name='Cost (USD)',
                    category_rotation=-45,
                    chart_size=CHART_SIZE_STANDARD,
                    plot_area_layout=PLOT_AREA_ROTATED_LABELS,
                    axis_font_size=10,
                )
                self._insert_pie_chart(
                    workbook,
                    summary_sheet,
                    'H41',
                    'Top 10 Accounts by Cost',
                    data_sheet.get_name(),
                    chart_row,
                    len(cost_by_account),
                    legend_position='right',
                    show_data_labels=True,
                    chart_size=CHART_SIZE_PIE,
                )
                chart_data_row += len(cost_by_account) + 3

            cost_by_region = sorted(
                ((region, float(cost)) for region, cost in report.costs.cost_by_region().items()),
                key=lambda x: x[1],
                reverse=True,
            )[:10]
            if cost_by_region:
                chart_row = self._write_chart_data(data_sheet, chart_data_row, cost_by_region)
                self._insert_column_chart(
                    workbook,
                    summary_sheet,
                    'H65',
                    'AWS Cost per Region',
                    data_sheet.get_name(),
                    chart_row,
                    len(cost_by_region),
                    x_axis_name='Region',
                    y_axis_name='Cost (USD)',
                    category_rotation=-35,
                    chart_size=CHART_SIZE_STANDARD,
                    plot_area_layout=PLOT_AREA_ROTATED_LABELS,
                    axis_font_size=10,
                )
                chart_data_row += len(cost_by_region) + 3

            cost_by_month = sorted(
                ((label, float(amount)) for label, amount in report.costs.cost_by_month().items()),
                key=lambda x: x[0],
            )
            if cost_by_month:
                chart_row = self._write_chart_data(data_sheet, chart_data_row, cost_by_month)
                self._insert_column_chart(
                    workbook,
                    summary_sheet,
                    'H91',
                    'Cost per Month',
                    data_sheet.get_name(),
                    chart_row,
                    len(cost_by_month),
                    x_axis_name='Month',
                    y_axis_name='Cost (USD)',
                    category_rotation=-30,
                    chart_size=CHART_SIZE_PIE,
                    plot_area_layout=PLOT_AREA_ROTATED_LABELS,
                    axis_font_size=10,
                )
                chart_data_row += len(cost_by_month) + 3

        resource_by_region = sorted(
            report.inventory.count_by_region().items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        if resource_by_region:
            chart_row = self._write_chart_data(data_sheet, chart_data_row, resource_by_region)
            self._insert_column_chart(
                workbook,
                summary_sheet,
                'R15',
                'Resources by Region',
                data_sheet.get_name(),
                chart_row,
                len(resource_by_region),
                x_axis_name='Region',
                y_axis_name='Resource Count',
                category_rotation=-35,
                chart_size=CHART_SIZE_STANDARD,
                plot_area_layout=PLOT_AREA_ROTATED_LABELS,
                axis_font_size=10,
            )
            chart_data_row += len(resource_by_region) + 3

        resource_by_type = sorted(
            report.inventory.count_by_type().items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        if resource_by_type:
            chart_row = self._write_chart_data(data_sheet, chart_data_row, resource_by_type)
            self._insert_column_chart(
                workbook,
                summary_sheet,
                'R41',
                'Top Resource Types',
                data_sheet.get_name(),
                chart_row,
                len(resource_by_type),
                chart_type='bar',
                show_table=False,
                show_data_labels=True,
                legend_position='none',
                x_axis_name='Resource Count',
                y_axis_name='Resource Type',
                chart_size=CHART_SIZE_HORIZONTAL_BAR,
                plot_area_layout=PLOT_AREA_HORIZONTAL_BAR,
                axis_font_size=10,
            )
            chart_data_row += len(resource_by_type) + 3

        instance_type_counts = sorted(
            report.inventory.attribute_distribution(
                "AWS::EC2::Instance",
                "Instance Type",
                report.metadata.generated_at,
            ).items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        if instance_type_counts:
            chart_row = self._write_chart_data(
                data_sheet,
                chart_data_row,
                [(label, float(value)) for label, value in instance_type_counts],
            )
            self._insert_column_chart(
                workbook,
                summary_sheet,
                'R71',
                'EC2 Instance Types',
                data_sheet.get_name(),
                chart_row,
                len(instance_type_counts),
                x_axis_name='Instance Type',
                y_axis_name='Instance Count',
                category_rotation=-40,
                chart_size=CHART_SIZE_PIE,
                plot_area_layout=PLOT_AREA_ROTATED_LABELS,
                axis_font_size=10,
            )
            chart_data_row += len(instance_type_counts) + 3

        top_at_risk = self._top_at_risk_accounts(report)
        if top_at_risk:
            chart_row = self._write_chart_data(
                data_sheet,
                chart_data_row,
                [
                    (
                        account_labels.get(acc_id, acc_id),
                        max(0.0, 100.0 - compliance_rate),
                    )
                    for acc_id, compliance_rate, _ in top_at_risk
                ],
            )
            self._insert_column_chart(
                workbook,
                summary_sheet,
                'R101',
                'Top Accounts at Risk',
                data_sheet.get_name(),
                chart_row,
                len(top_at_risk),
                show_table=False,
                show_data_labels=True,
                legend_position='none',
                x_axis_name='Account',
                y_axis_name='Non-compliance (%)',
                category_rotation=-45,
                chart_size=CHART_SIZE_RISK,
                plot_area_layout=PLOT_AREA_ROTATED_LABELS,
                axis_font_size=10,
            )
            chart_data_row += len(top_at_risk) + 3

    def _write_chart_data(
        self,
        sheet: Worksheet,
        start_row: int,
        data: list[tuple[str, float]],
    ) -> int:
        sheet.write(start_row, 0, 'Label')
        sheet.write(start_row, 1, 'Value')
        for idx, (label, value) in enumerate(data, start=1):
            sheet.write(start_row + idx, 0, label)
            sheet.write_number(start_row + idx, 1, value)
        return start_row

    def _insert_column_chart(
        self,
        workbook: Workbook,
        sheet: Worksheet,
        position: str,
        title: str,
        data_sheet_name: str,
        data_row: int,
        size: int,
        *,
        chart_type: str = 'column',
        show_table: bool = False,
        show_data_labels: bool = False,
        legend_position: Optional[str] = None,
        x_axis_name: Optional[str] = None,
        y_axis_name: Optional[str] = None,
        category_rotation: Optional[int] = None,
        chart_size: Optional[dict] = None,
        plot_area_layout: Optional[dict] = None,
        axis_font_size: int = 10,
    ) -> None:
        chart = workbook.add_chart({'type': chart_type})
        chart.add_series({
            'name': title,
            'categories': f"='{data_sheet_name}'!$A${data_row + 2}:$A${data_row + 1 + size}",
            'values': f"='{data_sheet_name}'!$B${data_row + 2}:$B${data_row + 1 + size}",
        })
        chart.set_title({'name': title})
        if legend_position:
            chart.set_legend({'position': legend_position})
        else:
            chart.set_legend({'none': True})
        chart.set_style(10)
        x_axis_opts: dict[str, Any] = {'major_gridlines': {'visible': False}, 'label_position': 'low'}
        y_axis_opts: dict[str, Any] = {'major_gridlines': {'visible': False}}
        if x_axis_name:
            x_axis_opts['name'] = x_axis_name
        if y_axis_name:
            y_axis_opts['name'] = y_axis_name
        if category_rotation is not None:
            x_axis_opts['num_font'] = {'rotation': category_rotation, 'size': axis_font_size}
        else:
            x_axis_opts['num_font'] = {'size': axis_font_size}

        # Set y-axis font size
        y_axis_opts['num_font'] = {'size': axis_font_size}

        chart.set_x_axis(x_axis_opts)
        chart.set_y_axis(y_axis_opts)
        if show_table:
            chart.set_table({'show_keys': False})
        if show_data_labels and hasattr(chart, "set_data_labels"):
            chart.set_data_labels({'value': True, 'font': {'size': 9}})

        # Use custom plot area layout if provided, otherwise use standard
        effective_plot_area = plot_area_layout if plot_area_layout is not None else PLOT_AREA_STANDARD
        chart.set_plotarea({'layout': effective_plot_area})

        # Use custom chart size if provided, otherwise use standard size
        effective_size = chart_size if chart_size is not None else CHART_SIZE_STANDARD
        chart.set_size(effective_size)
        sheet.insert_chart(position, chart, {'x_offset': 10, 'y_offset': 10})

    def _insert_pie_chart(
        self,
        workbook: Workbook,
        sheet: Worksheet,
        position: str,
        title: str,
        data_sheet_name: str,
        data_row: int,
        size: int,
        *,
        legend_position: str = 'right',
        show_data_labels: bool = True,
        chart_size: Optional[dict] = None,
    ) -> None:
        chart = workbook.add_chart({'type': 'pie'})
        chart.add_series({
            'name': title,
            'categories': f"='{data_sheet_name}'!$A${data_row + 2}:$A${data_row + 1 + size}",
            'values': f"='{data_sheet_name}'!$B${data_row + 2}:$B${data_row + 1 + size}",
            'data_labels': {
                'percentage': True,
                'category': False,
                'value': False,
                'font': {'size': 9},
            } if show_data_labels else {},
        })
        chart.set_title({'name': title})
        chart.set_legend({'position': legend_position, 'font': {'size': 9}})
        effective_size = chart_size if chart_size is not None else CHART_SIZE_PIE
        chart.set_size(effective_size)
        sheet.insert_chart(position, chart, {'x_offset': 10, 'y_offset': 10})

    def _format_duration(self, seconds: Optional[float]) -> str:
        if not seconds:
            return 'n/a'
        minutes, secs = divmod(int(seconds), 60)
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"
    def _write_accounts_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write enhanced Accounts summary sheet with detailed metrics."""
        sheet = workbook.add_worksheet('Accounts')

        # Headers
        headers = [
            'Account ID',
            'Account Name',
            'Account Email',
            'Status',
            'Resource Count',
            'Region Count',
            'Tag Compliance %',
        ]
        if report.has_costs():
            headers.append('Total Cost')

        for col, header in enumerate(headers):
            sheet.write(0, col, header, formats['header'])

        # Pre-calculate metrics
        resource_counts = report.inventory.count_by_account()
        cost_by_account = report.costs.cost_by_account() if report.costs else {}

        # Write data
        account_rows = list(report.accounts)
        if report.has_costs():
            account_rows.sort(
                key=lambda acc: cost_by_account.get(str(acc.id), Decimal('0')),
                reverse=True,
            )
        row = 1
        for account in account_rows:
            account_id = str(account.id)

            # Account ID
            sheet.write(row, 0, account_id)

            # Account Name
            sheet.write(row, 1, account.name)

            # Account Email
            sheet.write(row, 2, account.email)

            # Status
            sheet.write(row, 3, account.status.value)

            # Resource Count
            resource_count = resource_counts.get(account_id, 0)
            sheet.write(row, 4, resource_count, formats['number'])

            # Region Count (unique regions where this account has resources)
            account_resources = report.inventory.resources_by_account(account_id)
            unique_regions = set(r.region for r in account_resources)
            region_count = len(unique_regions)
            sheet.write(row, 5, region_count, formats['number'])

            # Tag Compliance % (percentage of resources with tags in this account)
            if resource_count > 0:
                tagged_count = sum(1 for r in account_resources if r.has_tags())
                tag_compliance = (tagged_count / resource_count) * 100
                sheet.write(row, 6, tag_compliance / 100, formats['percent'])
            else:
                sheet.write(row, 6, 0, formats['percent'])

            # Total Cost (if available)
            if report.has_costs():
                cost = cost_by_account.get(account_id, Decimal('0'))
                sheet.write(row, 7, float(cost), formats['currency'])

            row += 1

        # Auto-filter
        sheet.autofilter(0, 0, row - 1, len(headers) - 1)

        # Column widths
        sheet.set_column('A:A', 15)  # Account ID
        sheet.set_column('B:B', 30)  # Account Name
        sheet.set_column('C:C', 35)  # Account Email
        sheet.set_column('D:D', 12)  # Status
        sheet.set_column('E:E', 15)  # Resource Count
        sheet.set_column('F:F', 15)  # Region Count
        sheet.set_column('G:G', 18)  # Tag Compliance %
        if report.has_costs():
            sheet.set_column('H:H', 15)  # Total Cost

    def _write_regions_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write Regions summary sheet."""
        sheet = workbook.add_worksheet('Regions')

        # Headers
        headers = ['Region', 'Resource Count']
        if report.has_costs():
            headers.append('Total Cost')

        for col, header in enumerate(headers):
            sheet.write(0, col, header, formats['header'])

        # Data
        resource_counts = report.inventory.count_by_region()
        cost_by_region = report.costs.cost_by_region() if report.costs else {}

        # Sort by resource count
        regions_sorted = sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)

        row = 1
        for region, count in regions_sorted:
            sheet.write(row, 0, region)
            sheet.write(row, 1, count, formats['number'])

            if report.has_costs():
                cost = cost_by_region.get(region, Decimal('0'))
                sheet.write(row, 2, float(cost), formats['currency'])

            row += 1

        # Auto-filter
        sheet.autofilter(0, 0, row - 1, len(headers) - 1)

        # Column widths
        sheet.set_column('A:A', 20)
        sheet.set_column('B:B', 15)
        if report.has_costs():
            sheet.set_column('C:C', 15)

    def _write_resources_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write detailed Resources sheet."""
        sheet = workbook.add_worksheet('Resources')

        base_headers = [
            'Account ID',
            'Region',
            'Resource Type',
            'Resource ID',
            'Resource Name',
            'ARN',
            'Tags',
        ]

        attribute_headers = self._collect_attribute_headers(report.inventory.resources)
        headers = base_headers + attribute_headers

        for col, header in enumerate(base_headers):
            sheet.write(0, col, header, formats['header'])

        attr_start_col = len(base_headers)
        for idx, header in enumerate(attribute_headers):
            sheet.write(0, attr_start_col + idx, header, formats['header'])

        # Data
        row = 1
        reference_time = report.metadata.generated_at
        for resource in report.inventory.resources:
            sheet.write(row, 0, resource.account_id)
            sheet.write(row, 1, resource.region)
            sheet.write(row, 2, resource.resource_type)
            sheet.write(row, 3, resource.resource_id)
            sheet.write(row, 4, resource.resource_name or '')
            sheet.write(row, 5, resource.arn or '')

            # Format tags as key=value pairs
            tags_str = ', '.join(str(tag) for tag in resource.tags) if resource.tags else ''
            sheet.write(row, 6, tags_str)

            # Resource-specific attributes
            attribute_values = resource.attribute_values(reference_time)
            for idx, header in enumerate(attribute_headers):
                sheet.write(row, attr_start_col + idx, attribute_values.get(header, ''))

            row += 1

        # Auto-filter
        if row > 1:
            sheet.autofilter(0, 0, row - 1, len(headers) - 1)

        # Column widths
        sheet.set_column('A:A', 15)
        sheet.set_column('B:B', 15)
        sheet.set_column('C:C', 30)
        sheet.set_column('D:D', 30)
        sheet.set_column('E:E', 30)
        sheet.set_column('F:F', 50)
        sheet.set_column('G:G', 40)
        for idx in range(attr_start_col, attr_start_col + len(attribute_headers)):
            sheet.set_column(idx, idx, 20)

    def _write_costs_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write Costs breakdown sheet."""
        if not report.costs:
            return

        sheet = workbook.add_worksheet('Costs')

        # Headers
        headers = [
            'Account ID',
            'Service',
            'Region',
            'Amount',
            'Start Date',
            'End Date',
        ]
        if any(record.resource_id for record in report.costs.records):
            headers.append('Resource ID')

        for col, header in enumerate(headers):
            sheet.write(0, col, header, formats['header'])

        # Data
        row = 1
        display_start = report.metadata.cost_start_date
        display_end = report.metadata.cost_end_date
        cost_records = sorted(report.costs.records, key=lambda record: record.amount, reverse=True)

        for cost_record in cost_records:
            sheet.write(row, 0, cost_record.account_id)
            sheet.write(row, 1, cost_record.service)
            region_value = "" if cost_record.region == "ALL_REGIONS" else cost_record.region
            sheet.write(row, 2, region_value)
            sheet.write(row, 3, float(cost_record.amount), formats['currency'])
            sheet.write(
                row,
                4,
                (display_start or cost_record.start_date).isoformat(),
            )
            sheet.write(
                row,
                5,
                (display_end or cost_record.end_date).isoformat(),
            )
            if len(headers) > 6:
                sheet.write(row, 6, cost_record.resource_id or '')

            row += 1

        # Auto-filter
        if row > 1:
            sheet.autofilter(0, 0, row - 1, len(headers) - 1)

        # Column widths
        sheet.set_column('A:A', 15)
        sheet.set_column('B:B', 30)
        sheet.set_column('C:C', 15)
        sheet.set_column('D:D', 15)
        sheet.set_column('E:E', 12)
        sheet.set_column('F:F', 12)
        if len(headers) > 6:
            sheet.set_column('G:G', 48)

    def _write_security_posture_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write security posture dashboard combining compliance and TA insights."""
        sheet = workbook.add_worksheet('Security Posture')

        row = 0
        account_labels = self._account_labels(report)

        # ===== SECURITY OVERVIEW SECTION =====
        sheet.write(row, 0, 'Security Posture Overview', formats['title'])
        row += 2

        # Overall security metrics
        if report.compliance:
            sheet.write(row, 0, 'Overall Compliance Rate', formats['header'])
            overall_rate = report.compliance.overall_compliance_rate()
            cell_format = formats['good'] if overall_rate >= 95 else formats['warning'] if overall_rate >= 80 else formats['bad']
            combined_format = workbook.add_format({
                'num_format': '0.00%',
                'bg_color': cell_format.__dict__.get('bg_color'),
                'font_color': cell_format.__dict__.get('font_color'),
            })
            sheet.write(row, 1, overall_rate / 100, combined_format)
            row += 1

            sheet.write(row, 0, 'Total Violations', formats['header'])
            violations = report.compliance.total_violations()
            sheet.write(row, 1, violations, formats['number'])
            row += 1

            sheet.write(row, 0, 'Config Rules Evaluated', formats['header'])
            sheet.write(row, 1, report.compliance.total_rules(), formats['number'])
            row += 1

            sheet.write(row, 0, 'Rules with Violations', formats['header'])
            sheet.write(row, 1, report.compliance.rules_with_violations(), formats['number'])
            row += 2

        if report.advisor:
            sheet.write(row, 0, 'Trusted Advisor Checks', formats['header'])
            sheet.write(row, 1, report.advisor.total_checks(), formats['number'])
            row += 1

            sheet.write(row, 0, 'Checks with Issues', formats['header'])
            sheet.write(row, 1, report.advisor.checks_with_issues(), formats['number'])
            row += 1

            sheet.write(row, 0, 'Total Flagged Resources', formats['header'])
            sheet.write(row, 1, report.advisor.total_flagged_resources(), formats['number'])
            row += 2

        if report.identity_center:
            sheet.write(row, 0, 'IAM Identity Center Overview', formats['subtitle'])
            row += 1

            summary = report.identity_center
            sheet.write(row, 0, 'Instances', formats['header'])
            sheet.write(row, 1, summary.total_instances(), formats['number'])
            row += 1
            sheet.write(row, 0, 'Permission Sets', formats['header'])
            sheet.write(row, 1, summary.total_permission_sets(), formats['number'])
            row += 1
            sheet.write(row, 0, 'Account Assignments', formats['header'])
            sheet.write(row, 1, summary.total_assignments(), formats['number'])
            row += 1
            sheet.write(row, 0, 'Users', formats['header'])
            sheet.write(row, 1, sum(instance.user_count for instance in summary.instances), formats['number'])
            row += 1
            sheet.write(row, 0, 'Groups', formats['header'])
            sheet.write(row, 1, sum(instance.group_count for instance in summary.instances), formats['number'])
            row += 2

            sheet.write(row, 0, 'Instance Details', formats['subtitle'])
            row += 1
            headers = ['Instance ARN', 'Region', 'Permission Sets', 'Assignments', 'Sample Permission Sets']
            for col, header in enumerate(headers):
                sheet.write(row, col, header, formats['header'])
            row += 1

            for instance in summary.instances:
                sheet.write(row, 0, instance.instance_arn)
                sheet.write(row, 1, instance.region)
                sheet.write(row, 2, instance.permission_set_count, formats['number'])
                sheet.write(row, 3, instance.account_assignment_count, formats['number'])
                sheet.write(row, 4, ', '.join(instance.permission_sets[:5]))
                row += 1

            row += 2

        # ===== TOP ACCOUNTS AT RISK =====
        if report.compliance:
            sheet.write(row, 0, 'Top Accounts at Risk (by Compliance Rate)', formats['subtitle'])
            row += 1

            sheet.write(row, 0, 'Account', formats['header'])
            sheet.write(row, 1, 'Non-Compliant Resources', formats['header'])
            sheet.write(row, 2, 'Compliance Rate', formats['header'])
            row += 1

            top_at_risk = self._top_at_risk_accounts(report, limit=10)
            chart_data_start = row
            risk_col = 7

            labels = self._account_labels(report)

            for account_id, compliance_rate, violations_count in top_at_risk:
                sheet.write(row, 0, account_labels.get(account_id, account_id))
                sheet.write(row, 1, violations_count, formats['number'])

                cell_format = formats['good'] if compliance_rate >= 95 else formats['warning'] if compliance_rate >= 80 else formats['bad']
                combined_format = workbook.add_format({
                    'num_format': '0.00%',
                    'bg_color': cell_format.__dict__.get('bg_color'),
                    'font_color': cell_format.__dict__.get('font_color'),
                })
                compliance_fraction = compliance_rate / 100
                sheet.write(row, 2, compliance_fraction, combined_format)
                sheet.write(row, risk_col, max(0, 1 - compliance_fraction))
                row += 1

            if top_at_risk:
                chart = workbook.add_chart({'type': 'column'})
                chart.add_series({
                    'name': 'Risk (100 - compliance %)',
                    'categories': [sheet.get_name(), chart_data_start, 0, row - 1, 0],
                    'values': [sheet.get_name(), chart_data_start, risk_col, row - 1, risk_col],
                })
                chart.set_title({'name': 'Top Accounts at Risk'})
                chart.set_legend({'none': True})
                sheet.insert_chart(chart_data_start, 4, chart, {'x_offset': 10, 'y_offset': 10})
                row = max(row, chart_data_start + 16)

            row += 2

        # ===== TOP VIOLATED RULES =====
        if report.compliance:
            sheet.write(row, 0, 'Top 10 Most Violated Config Rules', formats['subtitle'])
            row += 1

            sheet.write(row, 0, 'Rule Name', formats['header'])
            sheet.write(row, 1, 'Non-Compliant Resources', formats['header'])
            sheet.write(row, 2, 'Total Evaluated', formats['header'])
            sheet.write(row, 3, 'Compliance Rate', formats['header'])
            row += 1

            # Aggregate violations by rule name
            rule_violations = {}
            for rule in report.compliance.config_rules:
                if rule.rule_name not in rule_violations:
                    rule_violations[rule.rule_name] = {
                        'violations': 0,
                        'compliant': 0,
                        'evaluated': 0
                    }
                rule_violations[rule.rule_name]['violations'] += rule.non_compliant_count
                rule_violations[rule.rule_name]['compliant'] += rule.compliant_count
                rule_violations[rule.rule_name]['evaluated'] += (rule.compliant_count + rule.non_compliant_count)

            # Sort by violations descending
            top_violated = sorted(rule_violations.items(), key=lambda x: x[1]['violations'], reverse=True)[:10]

            for rule_name, stats in top_violated:
                sheet.write(row, 0, rule_name)
                sheet.write(row, 1, stats['violations'], formats['number'])
                sheet.write(row, 2, stats['evaluated'], formats['number'])

                compliance_rate = (stats['compliant'] / stats['evaluated'] * 100) if stats['evaluated'] > 0 else 100.0
                cell_format = formats['good'] if compliance_rate >= 95 else formats['warning'] if compliance_rate >= 80 else formats['bad']
                combined_format = workbook.add_format({
                    'num_format': '0.00%',
                    'bg_color': cell_format.__dict__.get('bg_color'),
                    'font_color': cell_format.__dict__.get('font_color'),
                })
                sheet.write(row, 3, compliance_rate / 100, combined_format)
                row += 1

            row += 2

        # ===== TRUSTED ADVISOR FINDINGS BY SEVERITY =====
        if report.advisor:
            sheet.write(row, 0, 'Trusted Advisor Findings by Severity', formats['subtitle'])
            row += 1

            sheet.write(row, 0, 'Severity', formats['header'])
            sheet.write(row, 1, 'Check Count', formats['header'])
            row += 1

            findings_by_severity = report.advisor.findings_by_severity()
            for severity, count in findings_by_severity.items():
                sheet.write(row, 0, severity.value.upper())
                sheet.write(row, 1, count, formats['number'])
                row += 1

            row += 2

            pillar_map = self._ta_recommendations_by_pillar(report)
            if pillar_map:
                sheet.write(row, 0, 'Top Trusted Advisor Recommendations by Pillar', formats['subtitle'])
                row += 1
                sheet.write(row, 0, 'Pillar', formats['header'])
                sheet.write(row, 1, 'Recommendation', formats['header'])
                sheet.write(row, 2, 'Severity', formats['header'])
                sheet.write(row, 3, 'Flagged', formats['header'])
                row += 1

                for pillar, findings in pillar_map.items():
                    for finding in findings[:3]:
                        sheet.write(row, 0, pillar)
                        sheet.write(row, 1, finding.check_name)
                        sheet.write(row, 2, finding.status.value.upper())
                        sheet.write(row, 3, finding.resources_flagged, formats['number'])
                        row += 1
                row += 2

        if report.security_hub:
            sheet.write(row, 0, 'Security Hub Findings by Severity', formats['subtitle'])
            row += 1

            sheet.write(row, 0, 'Severity', formats['header'])
            sheet.write(row, 1, 'Finding Count', formats['header'])
            row += 1

            severity_counts = report.security_hub.findings_by_severity()
            for severity, count in severity_counts.items():
                sheet.write(row, 0, severity.value.title())
                sheet.write(row, 1, count, formats['number'])
                row += 1

            row += 2

        # Column widths
        sheet.set_column('A:A', 45)
        sheet.set_column('B:B', 20)
        sheet.set_column('C:C', 18)
        sheet.set_column('D:D', 18)
        sheet.set_column('E:E', 18)
        sheet.set_column('F:F', 18)
        sheet.set_column('G:G', 18)
        sheet.set_column('H:H', 0.1)

    def _write_compliance_details_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        if not report.compliance:
            return

        sheet = workbook.add_worksheet('Compliance Details')
        sheet.write(0, 0, 'AWS Config Compliance Details', formats['title'])
        sheet.write(1, 0, f"Total Rules with Violations: {report.compliance.rules_with_violations()}", formats['subtitle'])

        headers = [
            'Rule Name',
            'Account ID',
            'Compliant',
            'Non-Compliant',
            'Not Applicable',
            'Insufficient Data',
            'Compliance Rate',
        ]
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])

        row = 4
        for rule in report.compliance.config_rules:
            if rule.non_compliant_count == 0:
                continue
            sheet.write(row, 0, rule.rule_name)
            sheet.write(row, 1, rule.account_id)
            sheet.write(row, 2, rule.compliant_count, formats['number'])
            sheet.write(row, 3, rule.non_compliant_count, formats['number'])
            sheet.write(row, 4, rule.not_applicable_count, formats['number'])
            sheet.write(row, 5, rule.insufficient_data_count, formats['number'])

            rate = rule.compliance_rate() / 100
            color_fmt = formats['good'] if rate >= 0.95 else formats['warning'] if rate >= 0.80 else formats['bad']
            combined_format = workbook.add_format({
                'num_format': '0.00%',
                'bg_color': getattr(color_fmt, 'bg_color', None),
                'font_color': getattr(color_fmt, 'font_color', None),
            })
            sheet.write(row, 6, rate, combined_format)
            row += 1

        if row > 4:
            sheet.autofilter(3, 0, row - 1, len(headers) - 1)
        sheet.set_column('A:A', 45)
        sheet.set_column('B:B', 18)
        sheet.set_column('C:G', 18)

    def _write_trusted_advisor_details_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        if not report.advisor:
            return

        sheet = workbook.add_worksheet('Trusted Advisor Details')
        sheet.write(0, 0, 'Trusted Advisor Findings', formats['title'])
        sheet.write(1, 0, f"Total Checks: {report.advisor.total_checks()}", formats['subtitle'])

        headers = [
            'Check Name',
            'Category',
            'Status',
            'Resources Flagged',
            'Resources Ignored',
            'Resources Suppressed',
        ]
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])

        row = 4
        sorted_findings = sorted(
            (f for f in report.advisor.findings if f.status != AdvisorSeverity.OK),
            key=lambda finding: finding.status.value,
        )
        for finding in sorted_findings:
            sheet.write(row, 0, finding.check_name)
            sheet.write(row, 1, finding.category)
            sheet.write(row, 2, finding.status.value.upper())
            sheet.write(row, 3, finding.resources_flagged, formats['number'])
            sheet.write(row, 4, finding.resources_ignored, formats['number'])
            sheet.write(row, 5, finding.resources_suppressed, formats['number'])
            row += 1

        sheet.autofilter(3, 0, row - 1, len(headers) - 1)
        sheet.set_column('A:A', 45)
        sheet.set_column('B:C', 20)
        sheet.set_column('D:F', 18)

    def _write_security_hub_details_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        if not report.security_hub:
            return

        sheet = workbook.add_worksheet('Security Hub Details')
        sheet.write(0, 0, 'Security Hub Findings', formats['title'])

        open_findings = [
            finding
            for finding in report.security_hub.findings
            if finding.is_open()
        ]
        sheet.write(1, 0, f"Open Findings Considered: {len(open_findings)}", formats['subtitle'])

        headers = [
            'Control / Finding',
            'Severity',
            'Open Findings',
            'Accounts',
            'Sample Resources',
        ]
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])

        severity_order = [
            SecurityHubSeverity.CRITICAL,
            SecurityHubSeverity.HIGH,
            SecurityHubSeverity.MEDIUM,
            SecurityHubSeverity.LOW,
            SecurityHubSeverity.INFORMATIONAL,
        ]
        order_map = {severity: idx for idx, severity in enumerate(severity_order)}

        row = 4

        grouped: dict[str, dict] = {}
        for finding in open_findings:
            key = finding.title or finding.finding_id
            group = grouped.setdefault(
                key,
                {
                    'severity': finding.severity,
                    'count': 0,
                    'accounts': set(),
                    'resources': set(),
                },
            )
            group['severity'] = (
                finding.severity
                if order_map.get(finding.severity, 99) < order_map.get(group['severity'], 99)
                else group['severity']
            )
            group['count'] += 1
            if finding.account_id:
                group['accounts'].add(finding.account_id)
            resource_label = f"{finding.resource_type or ''} {finding.resource_id or ''}".strip()
            if resource_label:
                group['resources'].add(resource_label)

        sorted_groups = sorted(
            grouped.items(),
            key=lambda item: (
                order_map.get(item[1]['severity'], len(severity_order)),
                -item[1]['count'],
            ),
        )

        for title, data in sorted_groups:
            sheet.write(row, 0, title)
            sheet.write(row, 1, data['severity'].value.title())
            sheet.write(row, 2, data['count'], formats['number'])
            accounts_text = ', '.join(sorted(data['accounts'])) or 'n/a'
            sheet.write(row, 3, accounts_text)
            resource_list = list(data['resources'])[:10]
            sheet.write(row, 4, ', '.join(resource_list) if resource_list else 'n/a')
            row += 1

        if row > 4:
            sheet.autofilter(3, 0, row - 1, len(headers) - 1)
        sheet.set_column('A:A', 45)
        sheet.set_column('B:B', 18)
        sheet.set_column('C:C', 18)
        sheet.set_column('D:D', 30)
        sheet.set_column('E:E', 40)

    def _write_identity_center_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        summary = report.identity_center
        if not summary or not summary.instances:
            return

        sheet = workbook.add_worksheet('Identity Center')
        sheet.write(0, 0, 'IAM Identity Center Overview', formats['title'])
        sheet.write(1, 0, f"Instances discovered: {summary.total_instances()}", formats['subtitle'])
        sheet.write(2, 0, f"Total permission sets: {summary.total_permission_sets()}", formats['subtitle'])
        sheet.write(3, 0, f"Total assignments: {summary.total_assignments()}", formats['subtitle'])

        sheet.write(5, 0, 'Instance Details', formats['subtitle'])
        headers = [
            'Instance ARN',
            'Identity Store ID',
            'Region',
            'Permission Sets',
            'Assignments',
            'Users',
            'Groups',
            'Sample Permission Sets',
        ]
        for col, header in enumerate(headers):
            sheet.write(6, col, header, formats['header'])

        row = 7
        region_lookup = {}
        for instance in summary.instances:
            region_lookup[instance.instance_arn] = instance.region
            sheet.write(row, 0, instance.instance_arn)
            sheet.write(row, 1, instance.identity_store_id)
            sheet.write(row, 2, instance.region)
            sheet.write(row, 3, instance.permission_set_count, formats['number'])
            sheet.write(row, 4, instance.account_assignment_count, formats['number'])
            sheet.write(row, 5, instance.user_count, formats['number'])
            sheet.write(row, 6, instance.group_count, formats['number'])
            sheet.write(row, 7, ', '.join(instance.permission_sets[:10]))
            row += 1

        row += 2

        all_users = []
        for instance in summary.instances:
            for user in instance.users:
                all_users.append((instance.region, user))

        if all_users:
            sheet.write(row, 0, 'Sample Users', formats['subtitle'])
            row += 1
            user_headers = ['Instance Region', 'User ID', 'Username', 'Display Name', 'Email']
            for col, header in enumerate(user_headers):
                sheet.write(row, col, header, formats['header'])
            row += 1
            for region, user in all_users:
                sheet.write(row, 0, region)
                sheet.write(row, 1, user.user_id)
                sheet.write(row, 2, user.username or '')
                sheet.write(row, 3, user.display_name or '')
                sheet.write(row, 4, user.email or '')
                row += 1
            row += 2

        all_groups = []
        for instance in summary.instances:
            for group in instance.groups:
                all_groups.append((instance.region, group))

        if all_groups:
            sheet.write(row, 0, 'Sample Groups', formats['subtitle'])
            row += 1
            group_headers = ['Instance Region', 'Group ID', 'Display Name', 'Description']
            for col, header in enumerate(group_headers):
                sheet.write(row, col, header, formats['header'])
            row += 1
            for region, group in all_groups:
                sheet.write(row, 0, region)
                sheet.write(row, 1, group.group_id)
                sheet.write(row, 2, group.display_name or '')
                sheet.write(row, 3, group.description or '')
                row += 1
            row += 2

        assignment_rows = []
        for instance in summary.instances:
            for assignment in instance.assignments:
                assignment_rows.append((
                    region_lookup.get(assignment.instance_arn, ''),
                    assignment,
                ))

        if assignment_rows:
            sheet.write(row, 0, 'Sample Assignments', formats['subtitle'])
            row += 1
            assignment_headers = [
                'Instance Region',
                'Account ID',
                'Permission Set ARN',
                'Principal Type',
                'Principal Name',
            ]
            for col, header in enumerate(assignment_headers):
                sheet.write(row, col, header, formats['header'])
            row += 1
            for region, assignment in assignment_rows:
                sheet.write(row, 0, region)
                sheet.write(row, 1, assignment.account_id)
                sheet.write(row, 2, assignment.permission_set_arn)
                sheet.write(row, 3, assignment.principal_type)
                sheet.write(row, 4, assignment.principal_name)
                row += 1

        sheet.set_column('A:A', 25)
        sheet.set_column('B:B', 25)
        sheet.set_column('C:C', 20)
        sheet.set_column('D:D', 15)
        sheet.set_column('E:E', 15)
        sheet.set_column('F:F', 12)
        sheet.set_column('G:G', 12)
        sheet.set_column('H:H', 50)

    def _write_policies_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write organization policy summaries."""
        if not report.policies:
            return

        sheet = workbook.add_worksheet('Policies')
        sheet.write(0, 0, 'Organization Policies', formats['title'])
        row = 2

        sheet.write(row, 0, 'Policy Type', formats['header'])
        sheet.write(row, 1, 'Policies', formats['header'])
        sheet.write(row, 2, 'Targets', formats['header'])
        row += 1

        type_counts = []
        for policy_type, policies in report.policies.policies_by_type.items():
            total_targets = sum(policy.target_count for policy in policies)
            type_counts.append((policy_type, len(policies), total_targets))

        for policy_type, count, targets in sorted(type_counts, key=lambda x: x[0]):
            sheet.write(row, 0, self._format_policy_type(policy_type))
            sheet.write(row, 1, count, formats['number'])
            sheet.write(row, 2, targets, formats['number'])
            row += 1

        row += 2

        for policy_type, policies in report.policies.policies_by_type.items():
            sheet.write(row, 0, f"{self._format_policy_type(policy_type)} Policies", formats['subtitle'])
            row += 1

            headers = ['Policy Name', 'Description', 'Targets', 'Sample Targets']
            for col, header in enumerate(headers):
                sheet.write(row, col, header, formats['header'])
            row += 1

            for policy in policies:
                sheet.write(row, 0, policy.name)
                sheet.write(row, 1, policy.description or '')
                sheet.write(row, 2, policy.target_count, formats['number'])
                sampled_targets = ', '.join(policy.targets[:5])
                sheet.write(row, 3, sampled_targets)
                row += 1

            row += 2

        sheet.set_column('A:A', 28)
        sheet.set_column('B:B', 60)
        sheet.set_column('C:C', 12)
        sheet.set_column('D:D', 40)

    def _write_organizational_units_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
    ) -> None:
        """Write organizational unit hierarchy sheet."""
        hierarchy = report.org_hierarchy
        if not hierarchy or hierarchy.total_units() == 0:
            return

        sheet = workbook.add_worksheet('Organizational Units')
        sheet.write(0, 0, 'Organizational Unit Hierarchy', formats['title'])
        sheet.write(1, 0, f"Total OUs: {hierarchy.total_units()}", formats['subtitle'])
        sheet.write(2, 0, f"Root Nodes: {len(hierarchy.roots)}", formats['subtitle'])

        headers = [
            'OU Name',
            'OU ID',
            'Parent',
            'Depth',
            'Child OUs',
            'Account Count',
            'Sample Accounts',
        ]
        for col, header in enumerate(headers):
            sheet.write(4, col, header, formats['header'])

        row = 5
        for unit, depth in hierarchy.iter_units_depth_first():
            indent = '  ' * depth + unit.name
            sheet.write(row, 0, indent)
            sheet.write(row, 1, unit.id)
            parent = hierarchy.parent_name(unit.id) or ''
            sheet.write(row, 2, parent)
            sheet.write(row, 3, depth, formats['number'])
            sheet.write(row, 4, len(unit.child_ou_ids), formats['number'])
            sheet.write(row, 5, unit.account_count(), formats['number'])
            sample_accounts = ', '.join(unit.account_ids[:5])
            sheet.write(row, 6, sample_accounts)
            row += 1

        sheet.autofilter(4, 0, row - 1, len(headers) - 1)
        sheet.set_column('A:A', 40)
        sheet.set_column('B:B', 18)
        sheet.set_column('C:C', 25)
        sheet.set_column('D:E', 12)
        sheet.set_column('F:F', 15)
        sheet.set_column('G:G', 40)

    def _prepare_resource_type_sheet_names(self, report: ReportModel) -> "OrderedDict[str, str]":
        counts_by_type = report.inventory.count_by_type()
        ordered: "OrderedDict[str, str]" = OrderedDict()
        existing: set[str] = set()
        for resource_type, count in sorted(counts_by_type.items(), key=lambda x: x[1], reverse=True):
            sheet_name = self._sanitize_sheet_name(resource_type, count, existing)
            ordered[resource_type] = sheet_name
            existing.add(sheet_name)
        return ordered

    def _write_resource_type_summary_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
        type_sheet_names: "OrderedDict[str, str]",
        successfully_created: "set[str]",
        sheet: Optional[Worksheet] = None,
    ) -> None:
        """Write Resource Types Summary sheet with counts by type."""
        sheet = sheet or workbook.add_worksheet('Resource Types Summary')

        # Title
        sheet.write(0, 0, 'Resource Types Overview', formats['title'])
        sheet.write(1, 0, f'Total Resources: {report.inventory.total_count()}', formats['subtitle'])

        # Headers
        headers = ['Resource Type', 'Count', 'Percentage', 'Tagged', 'Untagged', 'Tag Coverage %', 'Details']
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])

        # Get counts by type
        counts_by_type = report.inventory.count_by_type()
        total_resources = report.inventory.total_count()

        # Calculate tag coverage per type
        type_data = []
        for resource_type, count in counts_by_type.items():
            resources_of_type = report.inventory.resources_by_type(resource_type)
            tagged = sum(1 for r in resources_of_type if r.has_tags())
            untagged = count - tagged
            tag_coverage = (tagged / count * 100) if count > 0 else 0

            type_data.append({
                'type': resource_type,
                'count': count,
                'percentage': (count / total_resources * 100) if total_resources > 0 else 0,
                'tagged': tagged,
                'untagged': untagged,
                'tag_coverage': tag_coverage,
            })

        # Sort by count descending
        type_data.sort(key=lambda x: x['count'], reverse=True)

        # Write data
        row = 4
        for data in type_data:
            sheet.write(row, 0, data['type'])
            sheet.write(row, 1, data['count'], formats['number'])
            sheet.write(row, 2, data['percentage'] / 100, formats['percent'])
            sheet.write(row, 3, data['tagged'], formats['number'])
            sheet.write(row, 4, data['untagged'], formats['number'])

            # Tag coverage with conditional formatting
            tag_cov = data['tag_coverage'] / 100
            if tag_cov >= 0.80:
                fmt = formats['good']
            elif tag_cov >= 0.50:
                fmt = formats['warning']
            else:
                fmt = formats['bad']

            # Combine format with percent format
            combined_fmt = workbook.add_format({
                'bg_color': fmt.bg_color if hasattr(fmt, 'bg_color') else None,
                'font_color': fmt.font_color if hasattr(fmt, 'font_color') else None,
                'num_format': '0.00%'
            })
            sheet.write(row, 5, tag_cov, combined_fmt)

            details_col = 6
            target_sheet = type_sheet_names.get(data['type'])
            # Only write hyperlink if the sheet was successfully created
            if target_sheet and data['type'] in successfully_created:
                sheet.write_url(
                    row,
                    details_col,
                    f"internal:'{target_sheet}'!A1",
                    formats['panel_cell'],
                    'View Sheet',
                )
            else:
                sheet.write(row, details_col, '', formats['panel_cell'])

            row += 1

        # Auto-filter
        if row > 4:
            sheet.autofilter(3, 0, row - 1, len(headers) - 1)

        # Column widths
        sheet.set_column('A:A', 40)
        sheet.set_column('B:B', 12)
        sheet.set_column('C:C', 12)
        sheet.set_column('D:D', 12)
        sheet.set_column('E:E', 12)
        sheet.set_column('F:F', 15)
        sheet.set_column('G:G', 15)

    def _write_resource_type_sheets(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
        type_sheet_names: "OrderedDict[str, str]",
    ) -> "set[str]":
        """Write individual sheets for each resource type.

        Returns:
            Set of resource type names for which sheets were successfully created.
        """
        successfully_created = set()
        counts_by_type = report.inventory.count_by_type()
        for resource_type, sheet_name in type_sheet_names.items():
            count = counts_by_type.get(resource_type, 0)

            try:
                sheet = workbook.add_worksheet(sheet_name)

                # Title
                sheet.write(0, 0, f'{resource_type}', formats['title'])
                sheet.write(1, 0, f'Total: {count} resources', formats['subtitle'])

                # Headers
                base_headers = [
                    'Account ID',
                    'Region',
                    'Resource ID',
                    'Resource Name',
                    'ARN',
                    'Tags',
                    'Creation Date',
                    'Status',
                    'Owner',
                    'Encryption',
                    'Public Exposure',
                    'Relationships',
                    'Dependencies',
                    'Health',
                ]

                resources = report.inventory.resources_by_type(resource_type)
                reference_time = report.metadata.generated_at
                attr_headers = self._collect_type_attribute_headers(resources, reference_time)
                headers = base_headers + attr_headers

                for col, header in enumerate(base_headers):
                    sheet.write(3, col, header, formats['header'])

                attr_start_col = len(base_headers)
                for idx, header in enumerate(attr_headers):
                    sheet.write(3, attr_start_col + idx, header, formats['header'])

                # Write data
                row = 4
                for resource in resources:
                    sheet.write(row, 0, resource.account_id)
                    sheet.write(row, 1, resource.region)
                    sheet.write(row, 2, resource.resource_id)
                    sheet.write(row, 3, resource.resource_name or '')
                    sheet.write(row, 4, resource.arn or '')

                    # Format tags
                    tags_str = ', '.join(str(tag) for tag in resource.tags) if resource.tags else ''
                    sheet.write(row, 5, tags_str)

                    enrichment = (resource.configuration or {}).get('inventory_enrichment', {})
                    standard_values = [
                        enrichment.get('creation_date', ''),
                        resource.status or enrichment.get('state', ''),
                        enrichment.get('owner', ''),
                        json.dumps(enrichment.get('encryption', ''), default=str),
                        json.dumps(enrichment.get('public_exposure', ''), default=str),
                        json.dumps(enrichment.get('relationships', {}), default=str, separators=(',', ':')),
                        json.dumps(enrichment.get('dependencies', {}), default=str, separators=(',', ':')),
                        enrichment.get('health', ''),
                    ]
                    for idx, value in enumerate(standard_values, start=6):
                        if isinstance(value, (dict, list, tuple)):
                            value = json.dumps(value, default=str, separators=(',', ':'))
                        sheet.write(row, idx, value)

                    attribute_values = resource.attribute_values(reference_time)
                    for idx, header in enumerate(attr_headers):
                        sheet.write(row, attr_start_col + idx, attribute_values.get(header, ''))

                    row += 1

                # Auto-filter
                if row > 4:
                    sheet.autofilter(3, 0, row - 1, len(headers) - 1)
                    sheet.freeze_panes(4, 0)

                # Column widths
                sheet.set_column('A:A', 15)
                sheet.set_column('B:B', 15)
                sheet.set_column('C:C', 30)
                sheet.set_column('D:D', 30)
                sheet.set_column('E:E', 50)
                sheet.set_column('F:F', 40)
                sheet.set_column('G:G', 10)
                for idx in range(attr_start_col, attr_start_col + len(attr_headers)):
                    sheet.set_column(idx, idx, 20)

                # Track successful creation
                successfully_created.add(resource_type)

            except Exception as e:
                logger.warning(f"Failed to create sheet for {resource_type}: {e}")
                continue

        return successfully_created

    def _write_tags_sheet(
        self,
        workbook: Workbook,
        report: ReportModel,
        formats: dict,
        sheet: Optional[Worksheet] = None,
    ) -> None:
        """Write a tab listing tagged resources."""
        tagged_resources = [resource for resource in report.inventory.resources if resource.has_tags()]
        if not tagged_resources:
            return

        sheet = sheet or workbook.add_worksheet('Resource Tags')
        sheet.write(0, 0, 'Resource Tags', formats['title'])
        sheet.write(
            1,
            0,
            f"Tagged Resources: {len(tagged_resources):,} / {report.inventory.total_count():,}",
            formats['subtitle'],
        )

        headers = [
            'Account ID',
            'Region',
            'Resource Type',
            'Resource Name',
            'Resource ID',
            'ARN',
            'Tags',
        ]
        for col, header in enumerate(headers):
            sheet.write(3, col, header, formats['header'])

        row = 4
        for resource in tagged_resources:
            sheet.write(row, 0, resource.account_id)
            sheet.write(row, 1, resource.region)
            sheet.write(row, 2, resource.resource_type)
            sheet.write(row, 3, resource.resource_name or '')
            sheet.write(row, 4, resource.resource_id)
            sheet.write(row, 5, resource.arn or '')
            tags_str = ', '.join(str(tag) for tag in resource.tags)
            sheet.write(row, 6, tags_str)
            row += 1

        if row > 4:
            sheet.autofilter(3, 0, row - 1, len(headers) - 1)
            sheet.freeze_panes(4, 0)

        sheet.set_column('A:A', 16)
        sheet.set_column('B:B', 15)
        sheet.set_column('C:C', 30)
        sheet.set_column('D:D', 30)
        sheet.set_column('E:E', 32)
        sheet.set_column('F:F', 48)
        sheet.set_column('G:G', 60)

    def _sanitize_sheet_name(self, resource_type: str, count: int, existing: Optional[set[str]] = None) -> str:
        """Sanitize resource type name for Excel sheet name."""
        # Remove AWS:: prefix if present
        name = resource_type.replace('AWS::', '').replace('::', '-')

        # Replace invalid characters
        invalid_chars = ['\\', '/', '*', '?', ':', '[', ']', "'"]
        for char in invalid_chars:
            name = name.replace(char, '-')

        # Add count suffix for uniqueness
        suffix = f' ({count})'
        max_len = 31 - len(suffix)

        # Truncate if needed
        if len(name) > max_len:
            name = name[:max_len]

        base_name = (name + suffix).strip()

        if not existing:
            return base_name

        candidate = base_name
        counter = 1
        while candidate in existing:
            extra = f"_{counter}"
            candidate = (base_name[: 31 - len(extra)]) + extra
            counter += 1

        return candidate

    def _top_at_risk_accounts(self, report: ReportModel, limit: int = 10) -> list[tuple[str, float, int]]:
        if not report.compliance:
            return []

        compliance_rates = report.compliance.compliance_by_account()
        violations: dict[str, int] = {}
        for rule in report.compliance.config_rules:
            violations[rule.account_id] = violations.get(rule.account_id, 0) + rule.non_compliant_count

        entries: list[tuple[str, float, int]] = []
        for account_id, rate in compliance_rates.items():
            entries.append((account_id, rate, violations.get(account_id, 0)))

        for account_id, violation_count in violations.items():
            if account_id not in compliance_rates:
                entries.append((account_id, 100.0, violation_count))

        if len(entries) < limit:
            seen = {acc_id for acc_id, _, _ in entries}
            for account in report.accounts:
                account_id = str(account.id)
                if account_id in seen:
                    continue
                entries.append((account_id, compliance_rates.get(account_id, 100.0), violations.get(account_id, 0)))
                seen.add(account_id)
                if len(entries) >= limit:
                    break

        entries.sort(key=lambda x: (x[1], -x[2]))
        return entries[:limit]

    def _account_labels(self, report: ReportModel) -> dict[str, str]:
        labels: dict[str, str] = {}
        for account in report.accounts:
            account_id = str(account.id)
            if account.name and account.name != account_id:
                labels[account_id] = f"{account.name} ({account_id})"
            else:
                labels[account_id] = account_id
        return labels

    def _ta_recommendations_by_pillar(self, report: ReportModel) -> "OrderedDict[str, list]":
        pillars: "OrderedDict[str, list]" = OrderedDict()
        if not report.advisor:
            return pillars

        for finding in report.advisor.findings:
            raw_categories = [part.strip() for part in finding.category.split(',')] if finding.category else []
            categories = [self._format_pillar_name(cat) for cat in raw_categories if cat]
            if not categories:
                categories = ['General']
            for pillar in categories:
                pillars.setdefault(pillar, []).append(finding)

        for pillar in pillars.keys():
            pillars[pillar] = sorted(pillars[pillar], key=lambda f: f.resources_flagged, reverse=True)

        return pillars

    @staticmethod
    def _format_pillar_name(raw: str) -> str:
        cleaned = raw.replace('_', ' ').strip()
        return cleaned.title() if cleaned else 'General'

    @staticmethod
    def _format_policy_type(raw: str) -> str:
        cleaned = raw.replace('_', ' ').replace('Policy', '').strip()
        return f"{cleaned.title()} Policy".strip() if cleaned else 'Policy'

    def _collect_type_attribute_headers(self, resources: list, reference_time: datetime) -> list[str]:
        """Collect ordered attribute labels for a resource type."""
        headers: list[str] = []
        for resource in resources:
            for label in resource.attribute_values(reference_time).keys():
                if label not in headers:
                    headers.append(label)
                if len(headers) >= MAX_ATTRIBUTE_COLUMNS:
                    return headers
        return headers

    def _collect_attribute_headers(self, resources: list) -> list[str]:
        """Collect static attribute headers for legacy Resources sheet."""
        headers: list[str] = []
        for resource in resources:
            for label in resource.attribute_headers():
                if label not in headers:
                    headers.append(label)
        if len(headers) > MAX_ATTRIBUTE_COLUMNS:
            return headers[:MAX_ATTRIBUTE_COLUMNS]
        return headers
