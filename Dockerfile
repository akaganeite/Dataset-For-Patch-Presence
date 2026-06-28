FROM python:3.11-slim

WORKDIR /artifact
COPY . /artifact

CMD ["python3", "scripts/smoke_test.py"]
