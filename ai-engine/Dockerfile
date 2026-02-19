FROM python:3.11-slim

WORKDIR /app

RUN pip install --upgrade pip

RUN pip install --no-cache-dir \
    opensearch-py==2.4.2 \
    scikit-learn \
    numpy \
    joblib

COPY feature_builder.py .
COPY analyzer.py .

CMD ["python", "-u", "analyzer.py"]
