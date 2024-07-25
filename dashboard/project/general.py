from dash.dependencies import Output, Input
from dash.long_callback import DiskcacheLongCallbackManager

from datetime import datetime
import sys

import project.computation as spark

## Diskcache
import diskcache
cache = diskcache.Cache("./cache")
long_callback_manager = DiskcacheLongCallbackManager(cache)

def register_callback_query(dm, app):
    @app.callback(
        Output(component_id='last_dump_message', component_property='children'),
        Output(component_id='date-picker-single', component_property='options'),
        Output(component_id='date-picker-single', component_property='value'),
        Input(component_id='last_dump_check', component_property='n_intervals'),
        Input(component_id='date-picker-single', component_property='value')
    )
    def update_dump_message(n_intervals, value):
        print("[INFO][update_dump_message] Checking for new any changes.")

        obs = ""
        last_date_commit = dm.last_commit()
        next_run = dm.compute_next_dump(last_date_commit) 

        if not last_date_commit:
            last_date_commit = "Empty"
        else:
            last_date_commit = last_date_commit.strftime("%Y-%m-%d %H:%M:%S")

        print(f"[INFO][update_dump_message] - ", app.scan_enabled)
        if app.scan_enabled:
            print(f"[INFO][update_dump_message] waiting_next_execution - Last dump {last_date_commit}. Next run will be at {next_run}", flush=True)
            if datetime.now() >= next_run:
                day_fmt1 = dm.waiting_next_file()
                if day_fmt1:
                    msg = f"Processing dump {day_fmt1}. It may take a while..."
                else:
                    msg = "Last dump: {last}.\nAt {new} none dump was found."

            msg = "Last dump: {last}.\nChecking for new data at {new}.".format(last=last_date_commit, new=next_run)

        else:
            msg = "Last dump: {last}".format(last=last_date_commit)

        dm.check_available_datasets()
        options = sorted(list(dm.available_datasets.keys()), reverse=True)
        if not value:
            if len(options) > 0:
                value = options[0]

        return msg, options, value


    @app.long_callback(
        Output(component_id='last_dump_message', component_property='children', allow_duplicate=True),
        Input(component_id='last_dump_message', component_property='children'), 
        running=[
            (Output("last_dump_check", "disabled"), True, False),
        ],
        manager=long_callback_manager,
        prevent_initial_call=True,
    )
    def processing_new_dump(msg):
        print("[INFO][processing_new_dump] ", msg)
        if "Processing dump" in msg:
            day_fmt1 = dm.waiting_next_file()
            if day_fmt1:
                
                last_date_commit = datetime.now()
                print(f"[INFO][processing_new_dump] - Starting computation - day_fmt1: {day_fmt1}...", flush=True)

                spark.run(day_str=day_fmt1)
                dm.commit_release(day_fmt1)
                dm.remove_old_data()
                dm.check_available_datasets()

                print("[INFO][processing_new_dump] - Finished", flush=True)
                next_run = dm.compute_next_dump(last_date_commit)

                last_date_commit = last_date_commit.strftime("%Y-%m-%d %H:%M:%S")
                msg = "Last dump: {last}.\nChecking for new data at {new}".format(last=last_date_commit, new=next_run)
        return msg



        
        
        
        
        