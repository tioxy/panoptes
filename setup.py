from distutils.core import setup
from setuptools import find_packages


setup(
    name='panoptes',
    version='0.2.0',
    author='Gabriel Tiossi',
    author_email='gabrieltiossi@gmail.com',
    packages=find_packages(),
    scripts=['panoptesctl'],
    url='http://pypi.python.org/pypi/panoptes/',
    license='LICENSE',
    description='The multi cloud security group analyzer.',
    long_description='https://github.com/tioxy/panoptes',
    install_requires=[
        'colorama>=0.3.7',
        'awscli>=1.14.68',
        'click>=6.7',
        'boto3>=1.6.21',
        'PyYAML>=3.12',
    ],
)
