"""Logging adapter to configure file-based logging for aws-ri."""

import logging
from pathlib import Path


class FileLoggingAdapter:
    """Configures loggers to write to a local file."""

    def __init__(self, log_file: Path):
        self.log_file = log_file

    def configure(self) -> None:
        """Configure logging handlers."""
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        handler = logging.FileHandler(self.log_file, encoding='utf-8')
        handler.setFormatter(logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        ))
        handler.setLevel(logging.INFO)

        target_loggers = [
            logging.getLogger('aws_ri.domain'),
            logging.getLogger('aws_ri.application'),
            logging.getLogger('aws_ri.infrastructure'),
        ]

        for logger in target_loggers:
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            logger.propagate = True
