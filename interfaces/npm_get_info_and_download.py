import requests
import pathlib
import typing
from urllib.parse import urlparse
import os
from download_compress import download_compressed

def download_and_get_package_info(directory: str, package_name: str, version=None) -> typing.Tuple[dict, str]:
    git_target = None
    if urlparse(package_name).hostname is not None and package_name.endswith('.git'):
        git_target = package_name

    if not package_name.startswith("@") and package_name.count("/") == 1:
        git_target = f"https://github.com/{package_name}.git"

    if git_target is not None:
        raise Exception("Git targets are not yet supported for npm")

    url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(url)

    if response.status_code != 200:
        raise Exception("Received status code: " + str(response.status_code) + " from npm")
    data = response.json()
    if "name" not in data:
        raise Exception(f"Error retrieving package: {package_name}")
    # if version is none, we only scan the last package
    # TODO: figure logs and log it when we do that
    version = data["dist-tags"]["latest"] if version is None else version

    details = data["versions"][version]

    tarball_url = details["dist"]["tarball"]
    file_extension = pathlib.Path(tarball_url).suffix
    zippath = os.path.join(directory, package_name.replace("/", "-") + file_extension)
    unzippedpath = zippath.removesuffix(file_extension)
    download_compressed(tarball_url, zippath, unzippedpath)

    return data, unzippedpath