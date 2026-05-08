FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files
COPY *.py .
COPY README.md .

# Default: run the synthetic benchmark (no API key needed)
CMD ["python", "benchmark.py", "--v2-only"]
