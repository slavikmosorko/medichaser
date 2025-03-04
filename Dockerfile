FROM python:3.9-alpine

# Install system dependencies
RUN apk add --no-cache \
    libxml2 \
    libxslt \
    libxml2-dev \
    libxslt-dev \
    gcc \
    musl-dev \
    python3-dev \
    py3-pip

WORKDIR /app/

# Copy setup.py
COPY ["setup.py", "/app/"]

# Install Python dependencies
RUN pip install --no-cache-dir "setuptools<58.0.0" rpds-py future rich && \
    pip install --no-cache-dir .

# Copy necessary files
COPY ["mediczuwacz.py", "medihunter_notifiers.py", "/app/"]

ENTRYPOINT ["python", "./mediczuwacz.py"]
