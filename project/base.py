import pandas as pd
import datetime
import os

dfs = {'day': None}
today = datetime.datetime.today().strftime('%Y-%m-%d')


def check_available_datasets():
    return sorted(os.listdir("./data/"))


def get_dataset(day, version):

    if day in check_available_datasets():
        print("Reading a new day:", day)
        
        df = pd.read_parquet(f'data/{day}/df_v{version}.parquet')
        df = pd.read_parquet(f'data/{day}/df_v{version}.parquet')
        df = pd.read_parquet(f'data/{day}/df_v{version}.parquet')
        df = pd.read_parquet(f'data/{day}/df_v{version}.parquet')

        if version == '2b':
            df['cpe_list'] = df['cpe_list'].str.join(', ')
            df['ip_list'] = df['ip_list'].str.join(', ')
            df['cve_list'] = df['cve_list'].str.join(', ')
        
        elif version == '3':
            df['org_list'] = df['org_list'].str.join(', ')
    return df



