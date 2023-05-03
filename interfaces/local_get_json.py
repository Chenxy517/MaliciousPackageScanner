import json
import os

def get_json_files_info(path):
    """
    Given a folder path, recursively finds all JSON files in the folder and its subfolders,
    reads their content, and stores the information in a dictionary. Returns the dictionary.
    """
    json_info = {}
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.json'):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = json.load(f)
                    json_info= content
                
    return json_info
