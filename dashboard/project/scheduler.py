from project.storage import DatasetManager
import project.computation as spark

from datetime import datetime
import time

def external_scheduler(mode="latest"):

    dm = DatasetManager()
    dm.check_available_datasets()

    while True:
        now = datetime.now()
        last_commit = dm.last_commit() # last timestamp that any dump was processed or None
        next_run = dm.compute_next_dump(last_commit) # Timestamp, based on env CRON_EXPRESSION, where a new processing attempt will be initiated
        diff = next_run - now
        if diff > 0:
            print(f"[INFO][external_scheduler] - New attempt for new files will be pending for {diff} seconds (at {next_run})")
            time.sleep(diff)
        
        new_files_exists = False
        while not new_files_exists:
            new_files = dm.waiting_next_file("latest") # Check if new files exists and retriving them

            for day_fmt1 in new_files:
                new_files_exists = True
                print(f"[INFO][external_scheduler] - Processing file {day_fmt1}")
                status = spark.start_processing(dm, day_fmt1)

            if not new_files_exists:
                print(f"[INFO][external_scheduler] - New files not found. Retrying in 60 seconds.")
                time.sleep(60)
