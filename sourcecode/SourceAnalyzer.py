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
        rules_dir = os.path.join("sourcecode", "rules", ecosystem.lower())
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
        has_issues = False
        messages = []

        # Process each file in the source code directory
        if path is not None and os.path.isdir(path):  # Fix the typo here
            for root, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    file_extension = os.path.splitext(file)[-1].lower()

                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Check each rule against the current file
                    for rule in self.rules:
                        conditions = rule.get('conditions', [])

                        # Check if the rule applies to this file based on conditions
                        apply_rule = all(
                            condition.get('file_extension') is None or file_extension in condition['file_extension']
                            for condition in conditions
                        )

                        if not apply_rule:
                            continue

                        # Look for the content pattern in the file content
                        pattern = rule.get('pattern')
                        if pattern is not None and re.search(pattern, content):
                            has_issues = True
                            messages.append(f"The file {file} matches the {rule['name']} rule: {rule['description']}\n")

        return has_issues, "\n".join(messages)




