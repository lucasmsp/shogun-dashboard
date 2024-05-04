#!/bin/bash

SPARK_UI_PORT=4040 SPARK_VCORES=4 SPARK_MEMORY=4g  SHODAN_FOLDER=./input_data/  RESULT_FOLDER=./output_data/ TLHOP_DATASETS_PATH=./output_data/tlhop_datasets/ python3 dashboard/app.py dev

