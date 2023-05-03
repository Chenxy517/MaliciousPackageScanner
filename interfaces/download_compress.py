import os
import requests
import tarsafe 
import zipfile


def download_compressed(url, archive_path, target_path):
        """Downloads a compressed file and extracts it
        Args:
            url (str): download link
            archive_path (str): path to download compressed file
            target_path (str): path to unzip compressed file
        """

        response = requests.get(url, stream=True)

        with open(archive_path, "wb") as f:
            f.write(response.raw.read())

        try:
            safe_extract(archive_path, target_path)
        finally:
            os.remove(archive_path)

def safe_extract(source_archive: str, target_directory: str) -> None:
    """
    safe_extract safely extracts archives to a target directory.
    This function does not clean up the original archive, and does not create the target directory if it does not exist.
    @param source_archive:      The archive to extract
    @param target_directory:    The directory where to extract the archive to
    @raise ValueError           If the archive type is unsupported
    """
    if source_archive.endswith('.tar.gz') or source_archive.endswith('.tgz'):
        tarsafe.open(source_archive).extractall(target_directory)
    elif source_archive.endswith('.zip') or source_archive.endswith('.whl'):
        with zipfile.ZipFile(source_archive, 'r') as zip:
            for file in zip.namelist():
                # Note: zip.extract cleans up any malicious file name such as directory traversal attempts
                # This is not the case of zipfile.extractall
                zip.extract(file, path=os.path.join(target_directory, file))
    else:
        raise ValueError("unsupported archive extension: " + target_directory)

