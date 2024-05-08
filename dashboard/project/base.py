import time
from croniter import croniter
from datetime import datetime
import os
import glob
from flask_login import UserMixin

import project.computation as r

CRON_EXPRESSION = os.environ.get("CRON_EXPRESSION", "*/1 * * * *")
SHODAN_FOLDER = os.environ.get("SHODAN_FOLDER", "/opt/input_data/")
RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")
RETRY_TIME = 3*60

users = {'admin': {'password': 'admin'}}
release_file = RESULT_FOLDER + "/RELEASE"


class User(UserMixin):
    def __init__(self, username):
        self.id = username

    def __str__(self):
        return self.id

def get_current_date():
    return datetime.today().strftime('%Y-%m-%d')

def new_file_is_found():
    return os.path.isfile(filepath)

def commit_release(day):
    with open(release_file, "w") as f:
        f.write(day)

def get_release():
    day = "19910615"
    if os.path.exists(release_file):
        with open(release_file, "r") as f:
            day = f.read()
    return day

def waiting_next_file():

    current_day = get_release().replace("-", "")
    next_date = current_day

    while next_date == current_day:
        filepath =  SHODAN_FOLDER + "/BR.{pattern}.json.bz2"
        available_dates = [os.path.basename(s)[3:-9] for s in sorted(glob.glob(filepath.format(pattern="*")))]
        for day in available_dates:
            if next_date < day:
                day = day[0:4]+"-"+day[4:6]+"-"+day[6:8]
                print("[INFO] Found a new Shodan dump for day: ", day)
                return day
                break
    
        print(f"[INFO]  New dataset not found. Retrying in {RETRY_TIME} seconds")
        time.sleep(RETRY_TIME)


def waiting_next_execution(dev_mode):
    while True:
        scheduler = croniter(CRON_EXPRESSION, datetime.now())
        next_run = scheduler.get_next(datetime)
        waiting_time = (next_run - datetime.now()).total_seconds()
        print(f"[INFO] - waiting_next_execution - Next run will be at {next_run} - ({waiting_time})s", flush=True)
        time.sleep(waiting_time)

        day_fmt1 = waiting_next_file()
        print("[INFO] - waiting_next_execution - Starting new run ...")
        if dev_mode:
            r.run_dummy(next_run)
        else:
            r.run(day_str=day_fmt1)
        print("Finished")
        commit_release(day_fmt1)
