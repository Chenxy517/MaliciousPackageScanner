import ast
import re

def read_setup_metadata(setup_file):
    with open(setup_file, 'r') as f:
        setup_contents = f.read()
    pattern = r"setup\(([\s\S]*)\)"
    match = re.search(pattern, setup_contents)
    if match:
        return(match.group(0))
    else:
        return "no result"




def get_setup_metadata(filename):
    
    setup_str=read_setup_metadata(filename)
    metadata = {}
    tree = ast.parse(setup_str)
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and node.value.func.id == 'setup':
            for keyword in node.value.keywords:
                if isinstance(keyword.value, ast.Str):
                    metadata[keyword.arg] = keyword.value.s
                elif isinstance(keyword.value, ast.List):
                    metadata[keyword.arg] = [ele.s for ele in keyword.value.elts]
    return metadata



metadata = get_setup_metadata('./example-malicious-0.0.2/setup.py')
print(metadata)
