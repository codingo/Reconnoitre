""" __Doc__ File handle class """
from setuptools import find_packages, setup
from lib.core.__version__ import __version__


def dependencies(imported_file):
    """ __Doc__ Handles dependencies """
    with open(imported_file) as file:
        return file.read().splitlines()


with open("README.md") as file:
    setup(
        name="Reconnoitre",
        license="GPLv3",
        description="A reconnaissance tool made for the OSCP labs to automate information gathering, "
                    "and service enumeration whilst creating a directory structure to store results,"
                    "findings and exploits used for each host, recommended commands to execute and directory structures for storing loot and flags.",
        long_description=file.read(),
        author="codingo",
        version=__version__,
        author_email="codingo@protonmail.com",
        url="http://github.com/codingo/Reconnoitre",
        packages=find_packages(exclude=('tests')),
        package_data={'Reconnoitre': ['*.txt']},
        entry_points={
            'console_scripts': [
                'Reconnoitre = Reconnoitre.Reconnoitre:main'
            ]
        },
        include_package_data=True)
