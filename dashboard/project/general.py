from dash.dependencies import Output, Input
from dash.long_callback import DiskcacheLongCallbackManager
from dash import no_update

from datetime import datetime
import project.computation as spark
import sys

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
        Input(component_id='date-picker-single', component_property='value'),
        Input(component_id='date-picker-single', component_property='options'),
    )
    def update_dump_message(n_intervals, value, old_opts):
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
                    day_fmt1 = day_fmt1[0]
                    msg = f"Processing dump {day_fmt1}. It may take a while..."
                else:
                    msg = "Last dump: {last}."

            msg = "Last dump: {last}.".format(last=last_date_commit, new=next_run)

        else:
            msg = "Last dump: {last}".format(last=last_date_commit)

        dm.check_available_datasets()
        options = dm.get_date_dumps()
        if not value:
            if len(options) > 0:
                value = options[0]

        if options == old_opts:
            options = no_update
            value = no_update

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
                day_fmt1 = day_fmt1[0]
                last_date_commit = datetime.now()
                status = spark.start_processing(dm, day_fmt1)
                # TODO: status
                next_run = dm.compute_next_dump(last_date_commit)
                last_date_commit = last_date_commit.strftime("%Y-%m-%d %H:%M:%S")
                msg = "Last dump: {last}.".format(last=last_date_commit)
        return msg



        
        
        
        
        
