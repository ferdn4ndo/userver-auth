#!/usr/bin/env python

from setuptools import setup, find_packages

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
    long_description = open('README.md').read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

version = '0.2'

setup(
    name='userver-auth',
    version=version,
    install_requires=requirements,
    author='Fernando Constantino',
    author_email='const.fernando@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    url='https://github.com/ferdn4ndo/userver-auth/',
    license='MIT',
    description='Authentication microservice based on Docker and Flask using JWT',
    long_description=long_description,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
    ],
)




from setuptools import setup

with open('README.md', 'r') as f:
    long_description = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
   name='userver-auth',
   version='1.0',
   description='Authentication microservice based on Docker and Flask',
   license='MIT',
   long_description=long_description,
   author='Fernando Constantino',
   author_email='const.fernando@gmail.com',
   url='https://github.com/ferdn4ndo/userver-auth',
   packages=['foo'],
   install_requires=requirements, #external packages as dependencies
   scripts=[
            'scripts/cool',
            'scripts/skype',
           ]
)
