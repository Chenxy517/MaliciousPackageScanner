from typing import Optional
from pathlib import Path
import yaml

from SourceAnalyzer import SourceAnalyzer


class NpmSourceAnalyzer(SourceAnalyzer):
    def __init__(self, rules_dir: str = "rules/npm"):
        super().__init__("NPM", rules_dir)

    def _load_rules(self, rules_file: str):
        # Override the parent's `_load_rules` method to load rules from a different YAML file
        # For example, "pypi_rules.yml" for PyPI packages
        with open(rules_file, 'r') as f:
            rules = yaml.safe_load(f)
        return rules['rules']
