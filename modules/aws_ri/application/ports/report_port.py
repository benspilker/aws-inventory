"""Application port for report writing."""

from abc import ABC, abstractmethod
from pathlib import Path

from aws_ri.domain.report_model import ReportModel


class ReportWriterPort(ABC):
    """Port for writing Excel reports.

    Infrastructure adapter implements this to use xlsxwriter/openpyxl.
    """

    @abstractmethod
    def write_report(self, report: ReportModel, output_path: Path) -> None:
        """Write report to Excel file.

        Args:
            report: ReportModel containing all data.
            output_path: Path to output .xlsx file.

        Raises:
            ReportWriterError: If unable to write report.
        """
        pass
