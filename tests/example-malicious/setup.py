import setuptools

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name='example-malicious', # Replace with your own username
    version='0.0.2',
    author='Bad actor',
    description='An example malicious package',
    long_description=long_description,
    long_description_content_type='text/markdown',
    package_dir={'': '.'},
    packages=setuptools.find_packages(where='.'),
    python_requires='>=3.6',
)
