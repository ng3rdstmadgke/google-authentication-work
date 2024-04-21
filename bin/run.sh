#!/bin/bash

PROJECT_DIR=$(cd $(dirname $0)/..; pwd)
cd $PROJECT_DIR
uvicorn main:app --reload