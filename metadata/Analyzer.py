from abc import abstractmethod
from datetime import datetime
from typing import Optional
import requests

import whois  # type: ignore


"""
Analyzer is the parent class of npm_analyzer and pypi_analyzer
"""
class Analyzer:
    # The name of the rule is dependent on the ecosystem and is provided by the implementing subclasses
    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem

    def _get_domain_creation_date(self, email_domain) -> tuple[Optional[datetime], bool]:
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
        except whois.parser.PywhoisError as e:
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
               version: Optional[str] = None) -> tuple[bool, str]:
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

        latest_project_release = self.get_project_latest_release_date(package_info)

        has_issues = False
        messages = []
        if len(emails) == 0:
            # No email is set for this package
            has_issues = True
            messages.append(f"No email found for this package")
            return has_issues, "\n".join(messages)

        for email in emails:
            sanitized_email = email.strip().replace(">", "").replace("<", "")
            email_domain = sanitized_email.split("@")[-1]
            domain_creation_date, domain_exists = self._get_domain_creation_date(email_domain)

            if not domain_exists:
                has_issues = True
                messages.append(f"The maintainer's email ({email}) domain does not exist and can likely be registered "
                                f"by an attacker to compromise the maintainer's {self.ecosystem} account")
            if domain_creation_date is None or latest_project_release is None:
                has_issues = True
                messages.append(f"Domain({email}) creation date or release date not found")
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
                messages.append(f"Your email address({email}) has been compromised in the following data breaches:")
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