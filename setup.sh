#!/bin/bash

# 스크립트 실행 중 에러가 발생하면 중지
set -e

# Python 패키지 설치 (pip 업그레이드 포함)
echo "업데이트 및 필수 패키지 설치 중..."
apt-get update && apt-get install -y python3 python3-pip

# 필요한 패키지 설치
echo "필요한 패키지를 설치 중..."
pip install -r requirements.txt

# Docker 이미지 빌드
IMAGE_NAME="Dockerfile"
echo "Docker 이미지 생성 중..."
docker build -t $IMAGE_NAME .

# Docker 컨테이너 실행
echo "Docker 컨테이너를 실행합니다..."
docker run --rm -v $(pwd):/app $IMAGE_NAME

echo "설치 및 실행이 완료되었습니다!"
