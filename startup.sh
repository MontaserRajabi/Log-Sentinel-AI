#!/bin/bash
# Azure App Service startup script for the Backend (FastAPI)
pip install -r requirements.txt --quiet
uvicorn src.api:app --host 0.0.0.0 --port 8000
