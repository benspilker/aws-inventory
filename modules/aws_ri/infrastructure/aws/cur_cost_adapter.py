"""Optional resource-level cost ingestion from an AWS Cost and Usage Report."""

import json
import time
from datetime import date
from decimal import Decimal
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aws_ri.application.ports.aws_ports import CostPort
from aws_ri.application.ports.exceptions import CostError
from aws_ri.domain.cost.cost_record import CostData, CostRecord


class CurCostAdapter(CostPort):
    """Read CUR rows through Athena; resource IDs are available when CUR is configured for them."""

    def __init__(self, session: boto3.Session, database: str, table: str,
                 workgroup: str = 'primary', output_location: Optional[str] = None):
        self.client = session.client('athena', region_name='us-east-1')
        self.database = database
        self.table = table
        self.workgroup = workgroup
        self.output_location = output_location

    def fetch_costs(self, start_date: date, end_date: date,
                    account_ids: Optional[list[str]] = None) -> CostData:
        accounts = ''
        if account_ids:
            values = ', '.join("'" + a.replace("'", "''") + "'" for a in account_ids)
            accounts = f" AND line_item_usage_account_id IN ({values})"
        query = f"""
SELECT line_item_usage_account_id, product_region, product_product_name,
       line_item_resource_id, line_item_unblended_cost,
       line_item_usage_start_date, line_item_usage_end_date
FROM \"{self.table}\"
WHERE line_item_usage_start_date >= TIMESTAMP '{start_date.isoformat()} 00:00:00'
  AND line_item_usage_start_date < TIMESTAMP '{end_date.isoformat()} 00:00:00'{accounts}
  AND line_item_line_item_type NOT IN ('Tax', 'Credit', 'Refund')
"""
        try:
            params = {'QueryString': query, 'QueryExecutionContext': {'Database': self.database}, 'WorkGroup': self.workgroup}
            if self.output_location:
                params['ResultConfiguration'] = {'OutputLocation': self.output_location}
            execution_id = self.client.start_query_execution(**params)['QueryExecutionId']
            self._wait(execution_id)
            rows = self._rows(execution_id)
            records = []
            for row in rows:
                try:
                    account, region, service, resource_id, amount, started, ended = row
                    value = Decimal(amount or '0')
                    if value > 0:
                        records.append(CostRecord(account or 'Unknown', service or 'Unknown', region or 'Unknown', value,
                                                  date.fromisoformat(started[:10]), date.fromisoformat(ended[:10]), resource_id=resource_id or None))
                except (ValueError, TypeError):
                    continue
            return CostData(records=records)
        except (ClientError, BotoCoreError, TimeoutError) as exc:
            raise CostError(f'Failed to fetch resource-level CUR costs: {exc}') from exc

    def _wait(self, execution_id: str) -> None:
        for _ in range(120):
            state = self.client.get_query_execution(QueryExecutionId=execution_id)['QueryExecution']['Status']['State']
            if state == 'SUCCEEDED':
                return
            if state in {'FAILED', 'CANCELLED'}:
                reason = self.client.get_query_execution(QueryExecutionId=execution_id)['QueryExecution']['Status'].get('StateChangeReason', state)
                raise CostError(f'Athena CUR query {state}: {reason}')
            time.sleep(1)
        raise TimeoutError('Timed out waiting for Athena CUR query')

    def _rows(self, execution_id: str) -> list[list[str]]:
        result = self.client.get_query_results(QueryExecutionId=execution_id)
        rows = result.get('ResultSet', {}).get('Rows', [])[1:]
        values = [[cell.get('VarCharValue', '') for cell in row.get('Data', [])] for row in rows]
        token = result.get('NextToken')
        while token:
            result = self.client.get_query_results(QueryExecutionId=execution_id, NextToken=token)
            values.extend([[cell.get('VarCharValue', '') for cell in row.get('Data', [])] for row in result.get('ResultSet', {}).get('Rows', [])])
            token = result.get('NextToken')
        return values
