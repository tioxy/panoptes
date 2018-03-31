from distutils.core import setup

with open('requirements.txt') as requirements_file:
    install_requirements = requirements_file.read().splitlines()

setup(
    name='Panoptes',
    version='0.1.0',
    author='Gabriel Tiossi',
    author_email='gabrieltiossi@gmail.com',
    packages=['panoptes'],
    scripts=['panoptesctl'],
    url='http://pypi.python.org/pypi/PanoptesCloud/',
    license='LICENSE',
    description='The multi cloud security group analyzer.',
    long_description=open('README.txt').read(),
    install_requires=install_requirements,
)
