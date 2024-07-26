#!/bin/bash
cd dashboard;
SPARK_UI_PORT=4040 SPARK_VCORES=4 SPARK_MEMORY=4g  SHODAN_FOLDER=../input_data/  RESULT_FOLDER=../output_data/ TLHOP_DATASETS_PATH=../output_data/tlhop_datasets/ POSTGRES_URL=0.0.0.0:5432 POSTGRES_USER=postgres POSTGRES_PASSWORD=postgres python3 app.py --host '127.0.0.1' --port 8080 --scan False
