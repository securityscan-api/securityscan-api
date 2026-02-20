#!/bin/bash
# SecurityScan API - Run Script

cd "$(dirname "$0")"

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Copy .env.example and configure it."
    exit 1
fi

# Run the server
echo "Starting SecurityScan API on http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo ""
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
