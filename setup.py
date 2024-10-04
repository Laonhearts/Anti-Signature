from setuptools import setup, find_packages

setup(
    name='AntiSignature',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'mysql-connector-python',
        'cx_Oracle',
        'scapy',
        'python-docx',
    ],
    entry_points={
        'console_scripts': [
            'antisig=main:main',
        ],
    },
)
