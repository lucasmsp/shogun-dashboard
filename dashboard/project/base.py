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
    next_date = get_release().replace("-", "")

    filepath =  SHODAN_FOLDER + "/BR.{pattern}.json.bz2"
    available_dates = [os.path.basename(s)[3:-9] for s in sorted(glob.glob(filepath.format(pattern="*")))]

    for day in available_dates:
        if next_date < day:
            day = day[0:4]+"-"+day[4:6]+"-"+day[6:8]
            print("[INFO][waiting_next_file] Found a new Shodan dump for day: ", day, flush=True)
            return day
    return None

def compute_next_dump(last_date_commit):
    if last_date_commit:
        scheduler = croniter(CRON_EXPRESSION, last_date_commit)
        next_run = scheduler.get_next(datetime)
    else:
        next_run = datetime.now()
    return next_run
