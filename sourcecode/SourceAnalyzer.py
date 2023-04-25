import os
import re
import yaml
from Analyzer import Analyzer
from typing import Optional


class SourceAnalyzer(Analyzer):
    def __init__(self, ecosystem: str, rules_dir: str):
        super().__init__(ecosystem)
        self.rules = self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str):
        rules = []
        for file_name in os.listdir(rules_dir):
            if file_name.endswith(".yml"):
                with open(os.path.join(rules_dir, file_name), 'r') as f:
                    data = yaml.safe_load(f)
                    rules.extend(data['rules'])
        return rules

    
    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        """
        Uses a package's source code to determine if the package contains any
        malware heuristics.
        Args:
            package_info (dict): dictionary representation of package information
        Returns:
            bool: True if malware is detected
            str:  A message describing the malware detected
        """
        has_issues = False
        messages = []
        
        # Look for patterns in the source code that match the rules defined in the YAML file
        if "source_code" in package_info:
            for rule in self.rules:
                pattern = rule.get('pattern')
                if pattern is None:
                    continue
                for line in package_info["source_code"]:
                    if re.search(pattern, line):
                        has_issues = True
                        messages.append(f"The package's source code matches the {rule['name']} rule: {rule['description']}")
        
        return has_issues, "\n".join(messages)
