#!/bin/bash

PROJECT_DIR=$(cd $(dirname $0)/..; pwd)
cd $PROJECT_DIR/app
poetry install
poetry run uvicorn app.main:app --env-file .env --reload