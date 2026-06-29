FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install in small batches to avoid timeout
RUN pip install --no-cache-dir --timeout=300 \
    fastapi uvicorn pydantic python-dotenv requests

RUN pip install --no-cache-dir --timeout=300 \
    langchain langchain-community langchain-groq

RUN pip install --no-cache-dir --timeout=300 \
    langchain-huggingface langchain-chroma langgraph langsmith

RUN pip install --no-cache-dir --timeout=300 \
    chromadb pypdf reportlab

RUN pip install --no-cache-dir --timeout=300 \
    sentence-transformers

RUN pip install --no-cache-dir --timeout=300 \
    mcp httpx-sse
    
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY . .

EXPOSE 8000
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]