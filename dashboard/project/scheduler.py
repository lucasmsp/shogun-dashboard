from project.storage import DatasetManager
from project.auxiliar import logging
from project.computation import start_processing
from datetime import datetime
import multiprocessing
import argparse
import time
import signal
import sys
import atexit
import psutil

current_proc = None

def cleanup_child_process():
    global current_proc
    if current_proc is not None and current_proc.is_alive():
        pid = current_proc.pid
        logging.info(f"Terminating child process {pid}...")
        current_proc.terminate()
        current_proc.join(timeout=10)
        if current_proc.is_alive():
            logging.warning(f"Child process {pid} did not terminate. Killing children and process...")
            try:
                parent = psutil.Process(pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
            except Exception:
                pass
            current_proc.kill()
            current_proc.join()
        logging.info("Child process cleanup completed.")
        current_proc = None

def signal_handler(signum, frame):
    logging.info(f"Scheduler received signal {signum}. Cleaning up and exiting...")
    cleanup_child_process()
    sys.exit(1)

# Register signal and exit handlers
atexit.register(cleanup_child_process)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def external_scheduler(mode="latest"):
    dm = DatasetManager()
    global current_proc
    
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
                    current_proc = proc
                    proc.start()
                    
                    if proc.is_alive():
                        proc.join(timeout=10*60)
                    
                    if not proc.is_alive():
                        if proc.exitcode == 0:
                            logging.info("Processo encerrado com sucesso")
                        else:
                            logging.error(f"Processo encerrado com erro (exitcode: {proc.exitcode})")
                        current_proc = None
                    else:
                        logging.error("Falha ao encerrar o processo no tempo limite. Terminar o processo...")
                        cleanup_child_process()
        
            elif not new_files_exists:
                logging.info(f"New files not found. Retrying in 60 seconds.")
                time.sleep(60)

if __name__ == '__main__':
    multiprocessing.set_start_method('spawn', force=True)
    parser = argparse.ArgumentParser(prog="tlhop-dashboard",
        description="This application is the scheduler of `tlhop-dashboard`, a dashboard with various panels for analyzing cybersecurity vulnerabilities using data from the Shodan search engine.",
        epilog="Thread-Limiting Holistic Open Platform (TLHOP) Project - DCC/UFMG - CERT.br"
    )
    parser.add_argument('--mode', required=False, default='latest', help="Use `latest` to process only the latest dump; `all` to process all new dumps;"\
                        " or `yyyymmdd` to a specific date.", type=str)
    args, _ = parser.parse_known_args()

    external_scheduler(mode=args.mode)

