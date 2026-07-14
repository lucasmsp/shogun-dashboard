from dash.dependencies import Input, Output, State
from dash import no_update, html, dcc, ctx, no_update
from flask_login import current_user

import project.query1_summary as query1_summary
import project.query2_orgs as query2_orgs
import project.query2_ips as query2_ips
import project.query3_cve as query3_cve
import project.query4_geo as query4_geo
import project.query5_report as query5_report
import project.query6_as as query6_as
import project.query7_ports as query7_ports
from project.auxiliar import logging


def _normalize_filters(filters):
    if not isinstance(filters, dict):
        return {}
    return filters


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
        logging.info("Checking for new any changes.")

        dm.check_available_datasets()
        last_date_commit = dm.last_commit()

        if not last_date_commit:
            last_date_commit = "Empty"
        else:
            last_date_commit = last_date_commit.strftime("%Y-%m-%d %H:%M:%S")

        msg = "Last dump: {last}".format(last=last_date_commit)

        options = dm.get_date_dumps()
        if not value:
            if len(options) > 0:
                value = options[0]

        if options == old_opts:
            options = no_update
            value = no_update

        return msg, options, value



    @app.callback(
        Output("page-content", "children"),
        Output('store-filters', 'data'),

        State('store-filters', 'data'),
        Input("url-redirect", "pathname")

    )
    def render_page_content(filters, pathname):
        pathname = pathname or "/dashboard/summary"
        filters = _normalize_filters(filters)
        logging.info(f"Pathname: {pathname} - filters: {filters}")

        if pathname == "/dashboard/ips":
            aggrid_key = 'query-2a-grid'
            filters = filters.get(aggrid_key, {})
            content = query2_ips.register_layout_query(filter_modal=filters)

        elif pathname == "/dashboard/orgs":
            aggrid_key = 'query-2b-grid'
            filters = filters.get(aggrid_key, {})
            content = query2_orgs.register_layout_query(filter_modal=filters)

        elif pathname == "/dashboard/cve":
            aggrid_key = 'query-3-ag'
            filters = filters.get(aggrid_key, {})
            content = query3_cve.register_layout_query(filter_modal=filters)

        elif pathname == "/dashboard/geo":
            content = query4_geo.register_layout_query(filter_modal={})

        elif pathname == "/dashboard/report":
            aggrid_key = 'query-5-ag'
            filters = filters.get(aggrid_key, {})
            content = query5_report.register_layout_query(filter_modal=filters)

        elif pathname == "/dashboard/as":
            content = query6_as.register_layout_query(filter_modal={})

        elif pathname == "/dashboard/ports":
            content = query7_ports.register_layout_query(filter_modal=filters)

        else:
            content = query1_summary.register_layout_query(filter_modal={})

        return content, {}

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
        # used in submenu (Aggregated vulnerabilities)
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
        # used in submenu (Aggregated vulnerabilities)
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


        
        
        
        
        
