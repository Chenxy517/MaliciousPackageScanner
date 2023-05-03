import random
import sys, os
sys.path.append(".")
sys.path.append("..")

from pypi_Analyzer import pypi_Analyzer
from interfaces.pypi_get_json import get_package_info



def test_pypi_metadata(name): 
    metadata=get_package_info(name)
    analyzer = pypi_Analyzer()
    has_issues, messages = analyzer.detect(metadata)
    if has_issues is True:
        print(messages)
    return has_issues

def main():

    file_path = os.path.join("pypi_test", "package_names.txt")
    with open(file_path) as file:
        lines = file.readlines()

    # generate 10 random integers between 1 and 100 (inclusive)
    random_indices = random.sample(range(1, 450897), 10)

    sample_packages = []

    # iterate over the random indices and append the corresponding lines to the list
    for index in random_indices:
        sample_packages.append(lines[index])

    # print the selected strings list
    print(sample_packages)

main()