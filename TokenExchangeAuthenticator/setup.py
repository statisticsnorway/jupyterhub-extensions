import io
import os
import re

from setuptools import find_packages
from setuptools import setup


def read(filename):
    filename = os.path.join(os.path.dirname(__file__), filename)
    text_type = type(u"")
    with io.open(filename, mode="r", encoding='utf-8') as fd:
        return re.sub(text_type(r':[a-z]+:`~?(.*?)`'), text_type(r'``\1``'), fd.read())


DEPENDENCIES = [
    'jupyterhub==1.3.0',
    'oauthenticator==0.12.3',
    'pyjwt==1.7.1'
]

setup(
    name="TokenExchangeAuthenticator",
    version="0.0.4",
    url="https://github.com/statisticsnorway/jupyterhub-extensions",
    license='MIT',

    author="Statistics Norway",
    author_email="bjorn.skaar@ssb.no",

    description="Jupyterhub oauth extension",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    keywords=["JupyterHub", "Authenticator", "Statistics Norway"],

    packages=find_packages(exclude=('tests', 'examples',)),

    install_requires=DEPENDENCIES,

    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
)
