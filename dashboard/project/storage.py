from deltalake import DeltaTable
from croniter import croniter
from datetime import datetime, timedelta
import pandas as pd
import glob
import os
import re

RESULT_FOLDER = os.environ.get("RESULT_FOLDER", "/opt/output_data/")
CRON_EXPRESSION = os.environ.get("CRON_EXPRESSION", "*/1 * * * *")
SHODAN_FOLDER = os.environ.get("SHODAN_FOLDER", "/opt/input_data/")
NUMBER_OF_DUMPS_TO_KEEP = int(os.environ.get("NUMBER_OF_DUMPS_TO_KEEP", 7))

class DatasetManager(object):
    
    def __init__(self):
        self.available_datasets = {}
        self.tlhop_epss_report_path = RESULT_FOLDER + "/tlhop-epss-dashboard.delta"
        self.tlhop_epss_views_path = RESULT_FOLDER + "/tlhop-epss-dashboard-view{}.delta"
        self.n_views = 4
        self.sampled_data = None

    def check_available_datasets(self):
        available_datasets = {}

        if os.path.exists(self.tlhop_epss_report_path):
            dt = DeltaTable(self.tlhop_epss_report_path)
            for i, commit in enumerate(dt.history()):

                if i == NUMBER_OF_DUMPS_TO_KEEP:
                    break

                elif commit.get("operation", "") == "WRITE":
                    timestamp_commit = datetime.fromtimestamp(commit['timestamp'] / 1e3)
                    if 'userMetadata' in commit:
                        day = re.findall("\d+", os.path.basename(commit['userMetadata']))[0]
                        date_commit = day[0:4]+"-"+day[4:6]+"-"+day[6:8]
                    else:
                        date_commit = timestamp_commit.strftime("%Y-%m-%d")

                    available_datasets[date_commit] = {"version": commit['version'],
                                                       "processing_timestamp": timestamp_commit}

        else:
            print(f"[ERROR][DatasetManager] File '{self.tlhop_epss_report_path}' not found")

        self.available_datasets = available_datasets
        print(f"[INFO][DatasetManager] Commits found: {self.available_datasets}")

    def last_commit(self):
        """
        Return the timestamp where the last dump was processed. 
        This information is not directly related to the timestamp dump itself.
        """
        dates = self.get_date_dumps()
        if len(dates) > 0:
            last_commit = dates[0]
            return self.available_datasets[last_commit]['processing_timestamp']
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
        dates = self.get_date_dumps()
        if len(dates) > 0:
            return dates[0]
        return "1991-06-15"

    def retrive_commit(self, day):
        return self.available_datasets.get(day, {"version": -1})['version']

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
    
    def get_report_dataset(self, day, columns=None, condition=None, single_output=False,
                        start=0, finish=-1, sort_by='score', ascending=False, compute_score=False, for_each=False, user_id=None):
        
        commit = self.retrive_commit(day)
        df = None

        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            print(f"Reading report of day {day}")
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            if for_each:
                if self.sampled_data is None:
                    self.sample_data(day, random_state=777, entries=600)

                if self.sampled_data is not None:
                    print(f"Using pre-sampled data for day {day} for user {user_id}")
                    df = self.sampled_data.copy()

                    if condition:
                        df = df.query(condition) 

                    num_users = 6
                    entries_per_user = 120

                    user_index = user_id % num_users if user_id is not None else 0
                    start_index = user_index * entries_per_user
                    end_index = start_index + entries_per_user

                    df = df.iloc[start_index:end_index]

                    if finish > 0:
                        df = df.iloc[start:finish]

            else:
                if single_output:
                    df = dt.filter(condition).head(1).to_pydict()
                else:
                    table = dt.to_table(filter=condition, columns=columns)
                    df = table.to_pandas()

                    if compute_score:
                        df['score'] = df['vulns_epss'].apply(lambda x: max(x) if isinstance(x, list) else 0)
                        df = df.drop(columns=['vulns_epss'])
                        df = df.sort_values(by=sort_by, ascending=ascending)

                    if finish > 0:
                        df = df.iloc[start:finish]

        return df
    
    def sample_data(self, day, random_state, entries):
        """
        Sample N random entries from the dataset and store them
        """
        commit = self.retrive_commit(day)

        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            print(f"[### SAMPLE_DATA ###] Sampling data for each user: {day} - Random state: {random_state}")
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            table = dt.to_table(columns=None)
            df = table.to_pandas()

            df['score'] = df['vulns_epss'].apply(lambda x: max(x) if isinstance(x, list) else 0)
            df = df.drop(columns=['vulns_epss'])

            self.sampled_data = df.sample(n=entries, random_state=random_state)

        else:
            self.sampled_data = pd.DataFrame()

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

        if len(self.available_datasets) > 0:
            threshold_date = self.get_date_dumps()[NUMBER_OF_DUMPS_TO_KEEP-1]
            real_processing_timestamp = self.available_datasets[threshold_date]['processing_timestamp']
            diff_seconds = (datetime.now() - real_processing_timestamp).total_seconds()
            retention_hours = int(divmod(diff_seconds, 3600)[0]) + 1

            filepaths = [self.tlhop_epss_report_path] + \
                        [self.tlhop_epss_views_path.format(code + 1) for code in range(self.n_views)]

            for filepath in filepaths:
                filepath = filepath.replace("//", "/")
                print(f"[INFO][DatasetManager][remove_old_data] - checking file {filepath}", flush=True)
                try:
                    stats1 = self.check_folder_stats(filepath)
                    dt = DeltaTable(filepath)
                    dt.vacuum(retention_hours=retention_hours, dry_run=False,  enforce_retention_duration=False)
                    stats2 = self.check_folder_stats(filepath)
                    print(f"[INFO][DatasetManager][remove_old_data] - Folder changed from {stats1} to {stats2}")
                except Exception as e:
                    print(f"[ERROR][DatasetManager][remove_old_data] - Error to vacuum file '{filepath}'", flush=True)
                    print(e, flush=True)

    @staticmethod
    def check_folder_stats(path):
        stats = {
            "number_of_files": len([name for name in os.listdir(path) if ".parquet" in name and '.crc' in name]),
            'folder_size':  sum(d.stat().st_size for d in os.scandir(path) if d.is_file())
        }
        return stats

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

    @staticmethod
    def compute_next_dump(last_date_commit):
        if last_date_commit:
            scheduler = croniter(CRON_EXPRESSION, last_date_commit)
            next_run = scheduler.get_next(datetime)
        else:
            next_run = datetime.now()
        return next_run

