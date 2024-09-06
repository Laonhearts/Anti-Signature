# 베이스 이미지로 Python 3.9을 사용합니다.
FROM python:3.9-slim

# 작업 디렉토리를 설정합니다.
WORKDIR /app

# 필요한 패키지들을 설치합니다. (argparse는 기본적으로 포함됨)
RUN pip install --no-cache-dir --upgrade pip

# 현재 디렉토리의 모든 파일을 Docker 컨테이너의 /app 디렉토리로 복사합니다.
COPY . .

# 컨테이너 실행 시 기본적으로 실행될 명령어를 정의합니다.
CMD ["python", "main.py"]
