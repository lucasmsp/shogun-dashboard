from deltalake import DeltaTable
from croniter import croniter
from datetime import datetime, timedelta
import pyarrow.dataset as ds
import pandas as pd
import numpy as np
import glob
import os
import re

RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")
CRON_EXPRESSION = os.environ.get("CRON_EXPRESSION", "*/1 * * * *")
SHODAN_FOLDER = os.environ.get("SHODAN_FOLDER", "/opt/input_data/")
RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")
RETENTION_VACUUM_HOURS = 24*7
class DatasetManager(object):
    
    def __init__(self):
        self.available_datasets = {}
        self.tlhop_epss_report_path = RESULT_FOLDER + "/tlhop-epss-dashboard.delta"
        self.tlhop_epss_views_path = RESULT_FOLDER + "/tlhop-epss-dashboard-view{}.delta"
        self.n_views = 3

    def check_available_datasets(self):
        available_datasets = {}
        last_vacuum_timestamp = None

        if os.path.exists(self.tlhop_epss_report_path):
            dt = DeltaTable(self.tlhop_epss_report_path)
            for commit in dt.history():
                if commit.get("operation", "") == "WRITE":
                    timestamp_commit = datetime.fromtimestamp(commit['timestamp'] / 1e3)

                    if 'userMetadata' in commit:
                        day = re.findall("\d+", os.path.basename(commit['userMetadata']))[0]
                        date_commit = day[0:4]+"-"+day[4:6]+"-"+day[6:8]
                    else:
                        date_commit = timestamp_commit.strftime("%Y-%m-%d")

                    if not last_vacuum_timestamp:   
                        available_datasets[date_commit] = commit['version']
                    elif timestamp_commit > last_vacuum_timestamp:
                        available_datasets[date_commit] = commit['version']
                    else:
                        # print(f"[date_commit] {timestamp_commit} (dump: {date_commit}) is already removed.")
                        pass

                elif (commit.get("operation", "") == "VACUUM END") and (not last_vacuum_timestamp):
                    last_vacuum_timestamp = datetime.fromtimestamp(commit['timestamp'] / 1e3) - timedelta(hours=RETENTION_VACUUM_HOURS)
        else:
            print(f"[ERROR][DatasetManager] File '{self.tlhop_epss_report_path}' not found")

        self.available_datasets = available_datasets
        print(f"[INFO][DatasetManager] Commits found: {self.available_datasets}")

    def last_commit(self):
        """
        Return the timestamp where the last dump was processed. 
        This information is not directly related to the timestamp dump itself.
        """

        if os.path.exists(self.tlhop_epss_report_path):
            dt = DeltaTable(self.tlhop_epss_report_path)
            for commit in dt.history():
                if commit.get("operation", "") == "WRITE":
                    last_timestamp = datetime.fromtimestamp(commit['timestamp'] / 1e3)
                    return last_timestamp
        return None
    
    def get_date_dumps(self):
        """
        """
        dates = sorted(list(self.available_datasets.keys()), reverse=True)
        return dates
    
    def last_dump_date(self):
        """
        Returns the timestamp of the newest dump
        """
        dates = sorted(list(self.available_datasets.keys()), reverse=True)
        if len(dates) > 0:
            return dates[0]
        return "1991-06-15"

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
    
    def get_report_dataset(self, day, columns=None, condition=None, single_output=False, start=0, finish=-1, sort_by='score', ascending=False, compute_score=False):
        commit = self.retrive_commit(day)
        df = None
        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            print(f"Reading report of day {day}")
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            if single_output:
                df = dt.filter(condition).head(1).to_pydict()
            else:

                table = dt.to_table(filter=condition, columns=columns)
                df = table.to_pandas()

                if compute_score:
                    df['score'] = df['vulns_scores'].apply(lambda x: x.get('epss', []) if isinstance(x, dict) else [])
                    df['score'] = df['score'].apply(lambda probs: 1 - np.prod([1 - p for p in probs]))
                    df = df.drop(columns=['vulns_scores'])
                    df = df.sort_values(by=sort_by, ascending=ascending)
                
                
                if finish > 0:
                    df = df.iloc[start:finish]

        return df

    def get_total_entries_new(self, day, condition=None):
        commit = self.retrive_commit(day)
        total_entries = 0
        if commit >= 0:
            filepath = self.tlhop_epss_report_path
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()
            if condition:
                total_entries = dt.filter(condition).count_rows()
            else:
                total_entries = dt.count_rows()
        return total_entries

    def remove_old_data(self):
        # default of 1 week
        filepaths = [self.tlhop_epss_report_path] + \
            [self.tlhop_epss_views_path.format(code+1) for code in range(self.n_views)]

        for filepath in filepaths:
            filepath = filepath.replace("//", "/")
            print(f"[INFO][DatasetManager][remove_old_data] - checking file {filepath}", flush=True)
            try:
                dt = DeltaTable(filepath)
                dt.vacuum(retention_hours=RETENTION_VACUUM_HOURS, dry_run=False,  enforce_retention_duration=False)                
            except:
                print(f"[ERROR][DatasetManager][remove_old_data] - error to vacuum file '{filepath}'",flush=True)

    def waiting_next_file(self, mode="latest"):
        next_date = self.last_dump_date().replace("-", "")

        filepath =  SHODAN_FOLDER + "/BR.{pattern}.json.bz2"
        available_dates = [os.path.basename(s)[3:-9] for s in sorted(glob.glob(filepath.format(pattern="*")))]

        found_files = [day[0:4]+"-"+day[4:6]+"-"+day[6:8] for day in available_dates if next_date < day]
        if len(found_files) > 0:
            if mode == "all":
                print("[INFO][waiting_next_file] Found a new Shodan dump for day: ", found_files, flush=True)
                return found_files
            elif mode == "latest":
                print("[INFO][waiting_next_file] Found a new Shodan dump for day: ", found_files[-1], flush=True)
                return [found_files[-1]]

        return None

    def compute_next_dump(self, last_date_commit):
        if last_date_commit:
            scheduler = croniter(CRON_EXPRESSION, last_date_commit)
            next_run = scheduler.get_next(datetime)
        else:
            next_run = datetime.now()
        return next_run

