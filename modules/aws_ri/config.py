"""Configuration management for aws-ri."""

import os
from pathlib import Path
from typing import Optional
import yaml
from dataclasses import dataclass, field


@dataclass
class Config:
    """Application configuration."""

    # AWS Config
    aggregator_name: Optional[str] = None
    default_profile: Optional[str] = None

    # Report defaults
    default_days: int = 30
    default_regions: list[str] = field(default_factory=list)
    default_output_dir: Optional[Path] = None

    # Features
    enable_costs: bool = True
    enable_posture: bool = True

    # Performance
    max_workers: int = 5

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> 'Config':
        """Load configuration from file.

        Args:
            config_path: Optional path to config file. If None, looks in default locations.

        Returns:
            Config instance.
        """
        if config_path is None:
            config_path = cls._find_config_file()

        if config_path and config_path.exists():
            return cls._load_from_yaml(config_path)

        return cls()

    @classmethod
    def _find_config_file(cls) -> Optional[Path]:
        """Find config file in default locations.

        Looks for config in:
        1. ~/.aws-ri/config.yaml
        2. ~/.aws-ri/config.yml
        3. ./.aws-ri.yaml
        4. ./.aws-ri.yml
        """
        locations = [
            Path.home() / '.aws-ri' / 'config.yaml',
            Path.home() / '.aws-ri' / 'config.yml',
            Path.cwd() / '.aws-ri.yaml',
            Path.cwd() / '.aws-ri.yml',
        ]

        for location in locations:
            if location.exists():
                return location

        return None

    @classmethod
    def _load_from_yaml(cls, config_path: Path) -> 'Config':
        """Load configuration from YAML file.

        Args:
            config_path: Path to YAML config file.

        Returns:
            Config instance.
        """
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f) or {}

        return cls(
            aggregator_name=data.get('aggregator_name'),
            default_profile=data.get('default_profile'),
            default_days=data.get('default_days', 30),
            default_regions=data.get('default_regions', []),
            default_output_dir=Path(data['default_output_dir']) if data.get('default_output_dir') else None,
            enable_costs=data.get('enable_costs', True),
            enable_posture=data.get('enable_posture', True),
            max_workers=data.get('max_workers', 5),
        )

    def to_yaml(self, config_path: Path) -> None:
        """Save configuration to YAML file.

        Args:
            config_path: Path to save config file.
        """
        config_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'aggregator_name': self.aggregator_name,
            'default_profile': self.default_profile,
            'default_days': self.default_days,
            'default_regions': self.default_regions,
            'default_output_dir': str(self.default_output_dir) if self.default_output_dir else None,
            'enable_costs': self.enable_costs,
            'enable_posture': self.enable_posture,
            'max_workers': self.max_workers,
        }

        with open(config_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
