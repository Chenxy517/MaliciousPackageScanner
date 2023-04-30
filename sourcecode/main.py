from SourceAnalyzer import SourceAnalyzer
import os


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


def main():
    ecosystem = get_ecosystem()
    directory = get_directory()

    analyzer = SourceAnalyzer(ecosystem)
    has_issues, messages = analyzer.detect(path=directory)

    if has_issues:
        print("\nPotential malware detected:\n")
        print(messages)
    else:
        print("No issues detected.")


if __name__ == "__main__":
    main()
