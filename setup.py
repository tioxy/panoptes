from setuptools import setup, find_packages
from os import path
from io import open


# Reading the README.md file and adding to package
here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


# Package setup definition
setup(
    name='panoptes',
    version='0.2.2',
    description='The multi cloud security group analyzer',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/tioxy/panoptes',
    author='Gabriel Tiossi',
    author_email='gabrieltiossi@gmail.com',
    keywords='panoptes aws security analysis cloud devops',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'panoptesctl = panoptes.panoptesctl:main',
        ],
    },
    license='LICENSE',
    install_requires=[
        'colorama>=0.3.7',
        'awscli>=1.14.68',
        'click>=6.7',
        'boto3>=1.6.21',
        'PyYAML>=3.12',
    ],
)
