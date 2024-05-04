from deltalake import DeltaTable

import pyarrow.dataset as ds
import pandas as pd

import time
from croniter import croniter
from datetime import datetime, timedelta
import os
from flask_login import UserMixin

users = {'admin': {'password': 'admin'}}

#cron_expression = "0 8 * * *"  # each day at 8h AM
cron_expression = "*/1 * * * *" # each 1m


class User(UserMixin):
    def __init__(self, username):
        self.id = username

    def __str__(self):
        return self.id

def get_current_date():
    return datetime.today().strftime('%Y-%m-%d')

def waiting_next_execution():
    while True:
        scheduler = croniter(cron_expression, datetime.now())
        next_run = scheduler.get_next(datetime)
        waiting_time = (next_run - datetime.now()).total_seconds()
        print(f"Next run will be at {next_run} - ({waiting_time})s")
        time.sleep(waiting_time)
        # TODO: IMPLEMENT A METHOD TO CHECK IF A NEW SHODAN FILE in `os.environ["SHODAN_FOLDER"]` folder is available. If not, sleeps for more X minutes
        print("Starting new run ...")
        run_dummy(next_run)
        print("Finished")
        #run

class DatasetManager(object):

    
    def __init__(self):
        self.available_datasets = {}
        self.tlhop_epss_report_path = "./data/tlhop-epss-dashboard.delta"
        self.tlhop_epss_views_path = "./data/tlhop-epss-dashboard-view{}.delta"
        self.filepaths = [
            "./data/tlhop-epss-dashboard.delta", 
            "./data/tlhop-epss-dashboard-view1.delta",
            "./data/tlhop-epss-dashboard-view2a.delta",
            "./data/tlhop-epss-dashboard-view2b.delta",
            "./data/tlhop-epss-dashboard-view3.delta",
            ]
        self.first_day = None
        self.last_day = None

    def check_available_datasets(self):
        available_datasets = {}
        try:
            dt = DeltaTable(self.tlhop_epss_report_path)
            for commit in dt.history():
                date_commit = datetime.fromtimestamp(commit['timestamp'] / 1e3).strftime("%Y-%m-%d")
                available_datasets[date_commit] = commit['version']
        except:
            print(f"File {tlhop_epss_report_path} not found")

        self.available_datasets = available_datasets
        print(f"[INFO] Commits found: {self.available_datasets}")
        tmp = sorted(self.available_datasets.keys())
        self.first_day = tmp[0]
        self.last_day = tmp[-1]

    def retrive_commit(self, day):
        return self.available_datasets.get(day, -1)

    def get_view_dataset(self, day, code):

        commit = self.retrive_commit(day)

        if commit >= 0:
            filepath = self.tlhop_epss_views_path.format(code)

            print(f"Reading {code} of day {day}")
            dt = DeltaTable(filepath, version=commit)
            df = dt.to_pandas()
        return df

    def get_report_dataset(self, day, columns=None, condition=None, single_output=False):

        commit = self.retrive_commit(day)

        if commit > 0:
            filepath = self.tlhop_epss_report_path

            print(f"Reading {code} of day {day}")
            dt = DeltaTable(filepath, version=commit)

            if single_output:
                dt = dt.filter(condition).head(1).to_pydict()
            else:
                df = dt.to_table(filter=condition, columns=columns).to_pandas()

        return df

    def remove_old_data(self):
        # default of 1 week
        for filepath in self.filepaths:
            DeltaTable(filepath)\
                .vacuum()



