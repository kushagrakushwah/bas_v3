FROM python:3.10-slim

WORKDIR /app

# Install dependencies required by asyncssh and general utilities
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# FIX: Copy the files into a specific bas_engine directory
COPY . /app/bas_engine/

EXPOSE 8000

# FIX: Run uvicorn using the module path (bas_engine.main:app)
CMD ["uvicorn", "bas_engine.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]