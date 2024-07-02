from deltalake import DeltaTable

from datetime import datetime
import pyarrow.dataset as ds
import pandas as pd
import os
import re

RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")

class DatasetManager(object):
    
    def __init__(self):
        self.available_datasets = {}
        self.tlhop_epss_report_path = RESULT_FOLDER + "/tlhop-epss-dashboard.delta"
        self.tlhop_epss_views_path = RESULT_FOLDER + "/tlhop-epss-dashboard-view{}.delta"
        self.n_views = 3

    def check_available_datasets(self):
        available_datasets = {}
        if os.path.exists(self.tlhop_epss_report_path):
            dt = DeltaTable(self.tlhop_epss_report_path)
            for commit in dt.history():
                if 'userMetadata' in commit:
                    day = re.findall("\d+", os.path.basename(commit['userMetadata']))[0]
                    date_commit = day[0:4]+"-"+day[4:6]+"-"+day[6:8]
                else:
                    date_commit = datetime.fromtimestamp(commit['timestamp'] / 1e3).strftime("%Y-%m-%d")
                available_datasets[date_commit] = commit['version']
        else:
            print(f"[ERROR][DatasetManager] File '{self.tlhop_epss_report_path}' not found")

        self.available_datasets = available_datasets
        print(f"[INFO][DatasetManager] Commits found: {self.available_datasets}")

    def last_commit(self):

        if os.path.exists(self.tlhop_epss_report_path):
            dt = DeltaTable(self.tlhop_epss_report_path)
            commit = dt.history()[0]
            last_timestamp = datetime.fromtimestamp(commit['timestamp'] / 1e3)
            return last_timestamp
        return None


    def retrive_commit(self, day):
        return self.available_datasets.get(day, -1)

    def get_view_dataset(self, day, code):

        commit = self.retrive_commit(day)
        if commit >= 0:
            filepath = self.tlhop_epss_views_path.format(code)

            print(f"[INFO][DatasetManager] Reading {code} of day {day}")
            dt = DeltaTable(filepath, version=commit)
            df = dt.to_pandas()
        else:
            df = pd.DataFrame()
        return df

    def get_report_dataset(self, day, columns=None, condition=None, single_output=False):

        commit = self.retrive_commit(day)
        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            print(f"[INFO][DatasetManager] Reading report of day {day}")
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            if single_output:
                df = dt.filter(condition).head(1).to_pydict()
            else:
                df = dt.to_table(filter=condition, columns=columns).to_pandas()
        else:
            df = pd.DataFrame()
        return df

    def remove_old_data(self):
        # default of 1 week
        filepaths = [self.tlhop_epss_report_path] + \
            [self.tlhop_epss_views_path.format(code+1) for code in range(self.n_views)]

        for filepath in filepaths:
            filepath = filepath.replace("//", "/")
            print(f"[INFO][DatasetManager][remove_old_data] - checking file {filepath}", flush=True)
            try:
                dt = DeltaTable(filepath)
                dt.vacuum(retention_hours=24*7, dry_run=False,  enforce_retention_duration=False)                
            except:
                print(f"[ERROR][DatasetManager][remove_old_data] - error to vacuum file '{filepath}'",flush=True)



