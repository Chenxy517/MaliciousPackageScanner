import json
import os
import pathlib
import whois
from copy import deepcopy
from datetime import datetime

import pytest
from _pytest.monkeypatch import MonkeyPatch

from npm_Analyzer import npm_Analyzer
from pypi_Analyzer import pypi_Analyzer

import resources.sample_project_info as PYPI_PACKAGE_INFO

with open("npm_data.json", "r") as file:
    NPM_PACKAGE_INFO = json.load(file)


class MockWhoIs:
    def __init__(self, date) -> None:
        self.creation_date = date


pypi_detector = pypi_Analyzer()
npm_detector = npm_Analyzer()


class TestEmail:

    @pytest.mark.parametrize("package_info, detector",
                             [(PYPI_PACKAGE_INFO, pypi_detector), (NPM_PACKAGE_INFO, npm_detector)])
    def test_compromised(self, package_info, detector):
        def mock_whois(domain):
            return MockWhoIs(datetime.today())

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = detector.detect(package_info)
        assert compromised

    @pytest.mark.parametrize("package_info, detector",
                             [(PYPI_PACKAGE_INFO, pypi_detector), (NPM_PACKAGE_INFO, npm_detector)])
    def test_safe(self, package_info, detector):
        def mock_whois(domain):
            return MockWhoIs(datetime(1990, 1, 31))

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = detector.detect(package_info)
        assert not compromised

    def test_email_domain_doesnt_exist(self):
        def mock_whois(domain):
            raise whois.parser.PywhoisError('No match for "nope.com".')

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = pypi_detector.detect(PYPI_PACKAGE_INFO)
        assert compromised

    def test_single_package_version(self):

        current_info = deepcopy(PYPI_PACKAGE_INFO)

        current_info["releases"] = {"1.0": [{
            "upload_time": "2023-03-06T00:41:25",
            "upload_time_iso_8601": "2023-03-06T00:41:25.953817Z"
        }]}
        try:
            pypi_detector.detect(current_info)
            pass  # we expect no exception to be thrown
        except Exception as e:
            pytest.fail(f"Unexpected exception thrown: {e}")