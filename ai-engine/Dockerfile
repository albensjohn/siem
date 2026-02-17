FROM python:3.9.18-slim

WORKDIR /app

RUN pip install --upgrade pip

RUN pip install --no-cache-dir opensearch-py==2.4.2

COPY analyzer.py .

CMD ["python", "-u", "analyzer.py"]
