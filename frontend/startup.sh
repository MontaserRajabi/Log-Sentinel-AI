#!/bin/bash
pip install flask requests python-dotenv gunicorn --quiet
python -m gunicorn --bind=0.0.0.0:8080 --chdir /home/site/wwwroot server:app
