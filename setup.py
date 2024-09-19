from setuptools import setup, find_packages

setup(
    name='anti_signature',
    version='1.0',
    description='Anti Signature: 파일 무결성 검사 및 랜섬웨어 감지 도구',
    author='Your Name',
    author_email='your.email@example.com',
    packages=find_packages(),
    install_requires=[
        'mysql-connector-python',
        'cx_Oracle',
        'scapy'
    ],
    entry_points={
        'console_scripts': [
            'anti-signature=main:main'
        ],
    },
)
