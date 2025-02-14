from setuptools import setup, find_packages
from re import search

with open('faraday_plugins/__init__.py', encoding='utf8') as f:
    version = search(r'__version__ = \'(.*?)\'', f.read()).group(1)

with open("README.md") as readme_file:
    readme = readme_file.read()

install_requires = [
    'Click',
    'simplejson',
    'requests',
    'lxml',
    'html2text',
    'beautifulsoup4',
    'pytz',
    'python-dateutil',
    'colorama',
    'tabulate',
    'packaging',
    'markdown',
    'tldextract'
]


setup(
    name='faraday-plugins',
    version=version,
    packages=find_packages(include=['faraday_plugins', 'faraday_plugins.*']),
    url='',
    license="GNU General Public License v3",
    long_description=readme,
    long_description_content_type="text/markdown",
    author='Faradaysec',
    author_email='devel@faradaysec.com',
    description='Faraday plugins package',
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
            'console_scripts': [
                'faraday-plugins=faraday_plugins.commands:cli',
            ],
        },
)
