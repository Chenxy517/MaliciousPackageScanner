import json
from abc import abstractmethod
from datetime import datetime
from typing import Optional
from dateutil import parser
from packaging import version
from pathlib import Path
from typing import Optional, Tuple
from typing import List
import argparse

import os
import re
import yaml

import requests

import whois  # type: ignore
from whois.parser import PywhoisError

"""
Analyzer is the parent class of npm_analyzer and pypi_analyzer
"""
class Analyzer:
    # The name of the rule is dependent on the ecosystem and is provided by the implementing subclasses
    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem

    def _get_domain_creation_date(self, email_domain) -> Tuple[Optional[datetime], bool]:
        """
        Gets the creation date of an email address domain
        Args:
            email_domain (str): domain of email address
        Raises:
            Exception: "Domain {email_domain} does not exist"
        Returns:
            datetime: creation date of email_domain
            bool:     if the domain is currently registered
        """

        try:
            domain_information = whois.whois(email_domain)
        except PywhoisError as e:
            # The domain doesn't exist at all, if that's the case we consider it vulnerable
            # since someone could register it
            return None, (not str(e).lower().startswith('no match for'))

        if domain_information.creation_date is None:
            # No creation date in whois, so we can't know
            return None, True

        creation_dates = domain_information.creation_date

        if type(creation_dates) is list:
            return min(creation_dates), True

        return creation_dates, True

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> Tuple[bool, str]:
        """
        Uses a package's information from PyPI's JSON API to determine
        if the package's email domain might have been compromised
        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output
        Raises:
            Exception: "Email for {package_info['info']['name']} does not exist."
        Returns:
            bool: True if email address has issue
        """

        emails = self.get_email_addresses(package_info)
        print(len(emails))
        if len(emails) == 0:
            # No e-mail is set for this package, hence no risk
            return False, "No e-mail found for this package"

        latest_project_release = self.get_project_latest_release_date(package_info)

        has_issues = False
        messages = []
        for email in emails:
            sanitized_email = email.strip().replace(">", "").replace("<", "")
            email_domain = sanitized_email.split("@")[-1]
            domain_creation_date, domain_exists = self._get_domain_creation_date(email_domain)

            if not domain_exists:
                has_issues = True
                messages.append(f"The maintainer's email ({email}) domain does not exist and can likely be registered "
                                f"by an attacker to compromise the maintainer's {self.ecosystem} account")
            if domain_creation_date is None or latest_project_release is None:
                continue
            if latest_project_release < domain_creation_date:
                has_issues = True
                messages.append(f"The domain name of the maintainer's email address ({email}) was"" re-registered after"
                                " the latest release of this ""package. This can be an indicator that this is a"""
                                " custom domain that expired, and was leveraged by"" an attacker to compromise the"
                                f" package owner's {self.ecosystem}"" account.")
        
            # API endpoint URL with the email address as a parameter
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

            # Set the headers with your API key (optional)
            headers = {
                "hibp-api-key": "b36f62e394e948a78667521d9621a82a"
            }

            # Send the GET request to the API
            response = requests.get(url, headers=headers)
        
            if response.status_code == 200:
                # The email address has been compromised, print the details of the data breaches
                has_issues = True
                messages.append(f"Your email address has been compromised in the following data breaches:")
                for breach in response.json():
                    messages.append(breach["Name"])
            else:
                # The email address has not been compromised or there was an error, print the response status code and reason
                messages.append(f"Request failed with status code {response.status_code}: {response.reason}")

        return has_issues, "\n".join(messages)

    def get_name(self) -> str:
        return "email_analyzer"

    def get_description(self) -> str:
        return self.description

    @abstractmethod
    def get_project_latest_release_date(self, package_info):
        pass

    @abstractmethod
    def get_email_addresses(self, package_info):
        pass
    
class npm_Analyzer(Analyzer):
    def __init__(self):
        super().__init__("npm")

    #def get_email_addresses(self, package_info: dict) -> list[str]:
        #return list(map(lambda x: x["email"], package_info["maintainers"]))
    
    def get_email_addresses(self, package_info: dict) -> List[str]:
        maintainers=find_values(package_info,"maintainers")[0]
        if maintainers is None:
            return []
        return [maintainer["email"] for maintainer in maintainers]

    def get_project_latest_release_date_(self, package_info) -> Optional[datetime]:
        """
        Gets the most recent release date of a Python project
        Args:
            releases (dict): PyPI JSON API's representation field
        Returns:
            datetime: creation date of the most recent in releases
        """
        if "dist-tags" not in package_info:
            return None
        latest_release_version = package_info["dist-tags"]["latest"]
        if "time" not in package_info:
            return None
        raw_date = package_info["time"][latest_release_version]
        release_date = parser.isoparse(raw_date).replace(tzinfo=None)
        return release_date
    
    def get_project_latest_release_date(self, package_info) -> Optional[datetime]:
        if "dist-tags" not in package_info:
            return None
        latest_release_version = package_info["dist-tags"]["latest"]
        if "time" not in package_info:
            return None
        raw_date = package_info["time"][latest_release_version]
        if not raw_date:
            return None
        release_date = datetime.strptime(raw_date, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=None)

        return release_date
    
    

class pypi_Analyzer(Analyzer):
    def __init__(self):
        super().__init__("pypi")

    def get_email_addresses(self, package_info: dict) -> List[str]:
        maintainers = package_info.get("maintainers")
        if maintainers is None:
            return []
        author_email = package_info["info"]["author_email"]
        maintainer_email = package_info["info"]["maintainer_email"]
        email = author_email or maintainer_email
        return [email]

    def get_project_latest_release_date(self, package_info) -> Optional[datetime]:
        """
        Gets the most recent release date of a Python project
        Args:
            releases (dict): PyPI JSON API's representation field
        Returns:
            datetime: creation date of the most recent in releases
        """
        releases = package_info["releases"]
        sorted_versions = sorted(
            releases.keys(), key=lambda r: version.parse(r), reverse=True
        )
        earlier_versions = sorted_versions[:-1] if len(sorted_versions) > 1 else sorted_versions

        for early_version in earlier_versions:
            version_release = releases[early_version]

            if len(version_release) > 0:  # if there's a distribution for the package
                upload_time_text = version_release[0]["upload_time_iso_8601"]
                release_date = parser.isoparse(upload_time_text).replace(tzinfo=None)
                return release_date
        raise Exception("could not find release date")

class Analyzer2:
    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem

    # Other methods can be added here...


class SourceAnalyzer(Analyzer2):
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

    
####################################################################
#tests
def find_values(d, search_key):
    result = []
    for key, value in d.items():
        if isinstance(value, dict):
            result.extend(find_values(value, search_key))
        elif key == search_key:
            result.append(value)
    return result
    
def test_npm_metadata():
    with open("npm_data.json") as f:
        metadata = json.load(f)
        
    metadata=metadata
    analyzer = npm_Analyzer()
    has_issues, messages = analyzer.detect(metadata)
    assert not has_issues, messages

def test_pypi_metadata():
    metadata=project_info
    analyzer = pypi_Analyzer()
    has_issues, messages = analyzer.detect(metadata)
    assert not has_issues, messages


def test_npm_sourcecode():
    path = "npm_sourcecode"
    name = "example-npm-project"
    version = "1.0.0"
    analyzer = npm_Analyzer()
    has_issues, messages = analyzer.detect(None, path, name, version)
    assert not has_issues, messages


def test_pypi_sourcecode():
    path = "pypi_sourcecode"
    name = "example-pypi-project"
    version = "1.0.0"
    analyzer = pypi_Analyzer()
    has_issues, messages = analyzer.detect(None, path, name, version)
    assert not has_issues, messages

def main():
    test_npm_metadata()
    #test_pypi_metadata()
    #test_npm_sourcecode()
    #test_pypi_sourcecode()
    print("All tests passed.")
    
main()