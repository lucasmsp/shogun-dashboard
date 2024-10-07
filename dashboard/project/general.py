from dash.dependencies import Input, Output, State
from dash.long_callback import DiskcacheLongCallbackManager
from dash import no_update, html, dcc, callback_context
from flask_login import current_user
import dash_bootstrap_components as dbc

import project.query1 as query1
import project.query2_orgs as query2_orgs
import project.query2_ips as query2_ips
import project.query3 as query3
import project.query4 as query4
import project.query5 as query5

from datetime import datetime
import project.computation as spark
import sys

## Diskcache
import diskcache
cache = diskcache.Cache("./cache")
long_callback_manager = DiskcacheLongCallbackManager(cache)

def register_callback_query(dm, app):

    @app.callback(
        Output(component_id='username-menu', component_property='label'),
        Output(component_id='admin-menu-item', component_property='style'),
        Input(component_id='username-menu', component_property='children')
    )
    def cur_user(style):
        if current_user.is_authenticated:

            if current_user.username == "admin":
                style = {'display': 'block'}

            return current_user.username, style
        else:
            return 'Empty', style
    

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

    tab1_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query1.register_layout_query(dm))], className="wrapper")),
        className="mt-3",
        id="tab1_content"
    )

    tab2_content_orgs = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query2_orgs.register_layout_query(dm))], className="wrapper"),
        ),
        className="mt-3",
        id="tab2_content_orgs"
    )

    tab2_content_ips = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query2_ips.register_layout_query(dm))], className="wrapper"),
        ),
        className="mt-3",
        id="tab2_content_ips"
    )

    tab3_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query3.register_layout_query(dm))], className="wrapper"),
        ),
        className="mt-3",
        id="tab3_content"
    )

    tab4_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query4.register_layout_query(dm))], className="wrapper"),
        ),
        className="mt-3",
        id="tab4_content"
    )

    tab5_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query5.register_layout_query(dm))], className="wrapper_table",
                     style={"width": "100%", "height": "100%"}),
        ),
        className="mt-3",
        id="tab5_content"
    )

    @app.callback(
        Output("page-content", "children"),
        [Input("url", "pathname")]
    )
    def render_page_content(pathname):
        print(pathname)
        if pathname == "/dashboard/view1":
            return tab1_content
        elif pathname == "/dashboard/view2a":
            return tab2_content_orgs
        elif pathname == "/dashboard/view2b":
            return tab2_content_ips
        elif pathname == "/dashboard/view3":
            return tab3_content
        elif pathname == "/dashboard/view4":
            return tab4_content
        elif pathname == "/dashboard/report":
            return tab5_content
        return html.Div(
            [
                html.H1("404: Not found", className="text-danger"),
                html.Hr(),
                html.P(f"The pathname {pathname} was not recognised..."),
            ],
            className="p-3 bg-light rounded-3",
        )

    @app.callback(
        Output("sidebar", "className"),
        [Input("sidebar-toggle", "n_clicks")],
        [State("sidebar", "className")],
    )
    def toggle_classname(n, classname):
        if n and classname == "":
            return "collapsed"
        return ""

    @app.callback(
        Output("collapse", "is_open"),
        [Input("navbar-toggle", "n_clicks")],
        [State("collapse", "is_open")],
    )
    def toggle_collapse(n, is_open):
        if n:
            return not is_open
        return is_open

    @app.callback(
        Output("submenu-v2-collapse", "is_open"),
        Input("submenu-v2", "n_clicks"),
        State("submenu-v2-collapse", "is_open"),
        prevent_initial_call='initial_duplicate'
    )
    def collapse_submenu(btn, is_open):
        ctx = callback_context
        print(ctx.triggered_id)
        if "submenu-v2" == ctx.triggered_id:
            return not is_open
        return is_open

    @app.callback(
        Output("arrow-v2", "className"),
        [Input("submenu-v2-collapse", "is_open")],
    )
    def set_navitem_class(is_open):
        if is_open:
            return "fas fa-chevron-down me-3"
        return "fas fa-chevron-right me-3"


        
        
        
        
        
