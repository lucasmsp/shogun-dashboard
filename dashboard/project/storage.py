from deltalake import DeltaTable

from datetime import datetime
import pyarrow.dataset as ds
import pandas as pd
import os

RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")

class DatasetManager(object):
    
    def __init__(self):
        self.available_datasets = {}
        self.tlhop_epss_report_path = RESULT_FOLDER + "/tlhop-epss-dashboard.delta"
        self.tlhop_epss_views_path = RESULT_FOLDER + "/tlhop-epss-dashboard-view{}.delta"
        self.filepaths = [
            RESULT_FOLDER + "/tlhop-epss-dashboard.delta", 
            RESULT_FOLDER + "/tlhop-epss-dashboard-view1.delta",
            RESULT_FOLDER + "/tlhop-epss-dashboard-view2a.delta",
            RESULT_FOLDER + "/tlhop-epss-dashboard-view2b.delta",
            RESULT_FOLDER + "/tlhop-epss-dashboard-view3.delta",
        ]
        self.first_day = None
        self.last_day = None

    def check_available_datasets(self):
        available_datasets = {}
        if os.path.exists(self.tlhop_epss_report_path):
            dt = DeltaTable(self.tlhop_epss_report_path)
            for commit in dt.history():
                date_commit = datetime.fromtimestamp(commit['timestamp'] / 1e3).strftime("%Y-%m-%d")
                available_datasets[date_commit] = commit['version']
        else:
            print(f"File '{self.tlhop_epss_report_path}' not found")

        self.available_datasets = available_datasets
        print(f"[INFO] Commits found: {self.available_datasets}")
        tmp = sorted(self.available_datasets.keys())
        if len(tmp) > 0:
            self.first_day = tmp[0]
            self.last_day = tmp[-1]

    def retrive_commit(self, day):
        return self.available_datasets.get(day, -1)

    def get_view_dataset(self, day, code):

        commit = self.retrive_commit(day)
        df = None
        if commit >= 0:
            filepath = self.tlhop_epss_views_path.format(code)

            print(f"Reading {code} of day {day}")
            dt = DeltaTable(filepath, version=commit)
            df = dt.to_pandas()
        return df

    def get_report_dataset(self, day, columns=None, condition=None, single_output=False):

        commit = self.retrive_commit(day)
        df = None
        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            print(f"Reading report of day {day}")
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            if single_output:
                df = dt.filter(condition).head(1).to_pydict()
            else:
                df = dt.to_table(filter=condition, columns=columns).to_pandas()

        return df

    def remove_old_data(self):
        # default of 1 week
        for filepath in self.filepaths:
            DeltaTable(filepath)\
                .vacuum()



