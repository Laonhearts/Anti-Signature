from setuptools import setup, find_packages

setup(
    name='anti_signature_tool',
    version='1.0.0',
    description='Anti Signature Tool: 파일 무결성 검사 및 랜섬웨어 감염 여부 확인 도구',
    author='Your Name',
    author_email='your.email@example.com',
    packages=find_packages(),
    install_requires=[
        'scapy',
        # 추가 필요한 패키지를 여기에 나열
    ],
    entry_points={
        'console_scripts': [
            'anti-signature=anti_signature_tool:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='==3.9',
)
