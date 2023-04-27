import os
import re
import yaml
from typing import Optional


class Analyzer:
    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem

    # Other methods can be added here...


class SourceAnalyzer(Analyzer):
    def __init__(self, ecosystem: str):
        super().__init__(ecosystem)
        rules_dir = os.path.join("rules", ecosystem.lower())
        self.rules = self._load_rules(rules_dir)


    def _load_rules(self, rules_dir: str):
        rules = []
        for file_name in os.listdir(rules_dir):
            if file_name.endswith(".yml"):
                with open(os.path.join(rules_dir, file_name), 'r') as f:
                    data = yaml.safe_load(f)
                    rules.extend(data['rules'])
        return rules


    def detect(self, path: Optional[str] = None, name: Optional[str] = None,
           version: Optional[str] = None) -> tuple[bool, str]:
        """
        Uses a package's source code to determine if the package contains any
        malware.
        Args:
            path (str): The path to the directory containing the package's source code.
        Returns:
            bool: True if malware is detected
            str:  A message describing the malware detected
        """
        has_issues = False
        messages = []
        
        package_info = {"source_code": []}

        # Read source code files from the directory
        if path is not None and os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.readlines()
                        package_info["source_code"].extend(content)

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

