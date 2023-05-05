import os

from metadata.npm_Analyzer import npm_Analyzer
from metadata.pypi_Analyzer import pypi_Analyzer
from sourcecode.SourceAnalyzer import SourceAnalyzer
from interfaces.pypi_get_json import get_package_info
from interfaces.npm_get_info_and_download import download_and_get_package_info
from interfaces.pypi_download import download_package
   
def get_ecosystem() -> str:
    while True:
        ecosystem = input("Enter the package ecosystem (NPM or PYPI): ").strip().upper()
        if ecosystem in ["NPM", "PYPI"]:
            return ecosystem
        else:
            print("Invalid input. Please enter either 'NPM' or 'PYPI'.")


def get_directory() -> str:
    while True:
        directory = input("Enter the path to the directory containing the package source code: ").strip()
        if os.path.isdir(directory):
            return directory
        else:
            print("Invalid directory path. Please enter a valid path.")   
            
def find_values(d, search_key):
    result = []
    for key, value in d.items():
        if isinstance(value, dict):
            result.extend(find_values(value, search_key))
        elif key == search_key:
            result.append(value)
    return result

def get_name() -> str:
    while True:
        name = input("Enter the name of the PYPI package you want to test ").strip()
        return name

def test_pypi_metadata(name):
    
    metadata=get_package_info(name)
    analyzer = pypi_Analyzer()
    has_issues, messages = analyzer.detect(metadata)
    if has_issues is True:
        print(messages)
    return has_issues
    
def test_pypi_sourcecode(name):
    ecosystem="PYPI"
    directory = "./download/"+name
    print("directory:",directory)

    analyzer = SourceAnalyzer(ecosystem)
    has_issues, messages = analyzer.detect(path=directory)
    
    if has_issues:
        print("Potential malware detected:")
        print(messages)
    else:
        print("No issues detected in source code.")
    return has_issues

def test_npm_metadata(info):
    metadata=info
    analyzer = npm_Analyzer()
    has_issues, messages = analyzer.detect(metadata)
    assert not has_issues, messages

def test_npm_sourcecode(path):
    ecosystem="NPM"

    analyzer = SourceAnalyzer(ecosystem)
    has_issues, messages = analyzer.detect(path)

    if has_issues:
        print("Potential malware detected:")
        print(messages)
    else:
        print("No issues detected.")
    return has_issues

def main():
    ecosystem = get_ecosystem()
    if ecosystem=="NPM":
        name=get_name()
        info,path=download_and_get_package_info("./download_npm",name)
        test_npm_metadata(info)
        test_npm_sourcecode(path)
    if ecosystem=="PYPI":
        name=get_name()
        download_package(name,"./download")
        test_pypi_metadata(name)
        has_issues=test_pypi_sourcecode(name)

main()
