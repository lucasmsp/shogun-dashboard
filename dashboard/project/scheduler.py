from project.storage import DatasetManager
from project.auxiliar import logging
from project.computation import start_processing
from datetime import datetime
import multiprocessing
import argparse
import time


def external_scheduler(mode="latest"):

    dm = DatasetManager()
    
    while True:
        dm.check_available_datasets()
        now = datetime.now()
        last_commit = dm.last_commit() # last timestamp that any dump was processed or None
        next_run = dm.compute_next_dump(last_commit) # Timestamp, based on env CRON_EXPRESSION, where a new processing attempt will be initiated
        diff = (next_run - now).total_seconds()
        if diff > 0:
            logging.info(f"New attempt for new files will be pending for {diff} seconds (at {next_run})")
            time.sleep(diff)
        
        new_files_exists = False
        while not new_files_exists:
            new_files = dm.waiting_next_file(mode) # Check if new files exists and retriving them
            if new_files:
                for day_fmt1 in new_files:
                    new_files_exists = True
                    logging.info(f"Processing file {day_fmt1}")
                    proc = multiprocessing.Process(target=start_processing, args=(dm, day_fmt1), daemon=False)
                    proc.start()
                    
                    if proc.is_alive():
                        proc.join(timeout=10*60)
                    
                    if not proc.is_alive():
                        print("Processo encerrado com sucesso")
                    else:
                        print("Falha ao encerrar o processo")
        
            elif not new_files_exists:
                logging.info(f"New files not found. Retrying in 60 seconds.")
                time.sleep(60)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="tlhop-dashboard",
        description="This application is the scheduler of `tlhop-dashboard`, a dashboard with various panels for analyzing cybersecurity vulnerabilities using data from the Shodan search engine.",
        epilog="Thread-Limiting Holistic Open Platform (TLHOP) Project - DCC/UFMG - CERT.br"
    )
    parser.add_argument('--mode', required=False, default='latest', help="Use `latest` to process only the latest dump; `all` to process all new dumps;"\
                        " or `yyyymmdd` to a specific date.", type=str)
    args, _ = parser.parse_known_args()

    external_scheduler(mode=args.mode)
