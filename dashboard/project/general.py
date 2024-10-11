from dash.dependencies import Input, Output, State
from dash import no_update, html, dcc, ctx, no_update
from flask_login import current_user

from project.layout import tab1_content, tab2_content_orgs, tab2_content_ips, tab3_content, tab4_content, tab5_content

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
        Output("url-redirect", "pathname"),
        [Input("url-redirect", "pathname")]
    )
    def render_page_content(pathname):
        print("render_page_content:", pathname)

        if pathname == "/dashboard/view1":
            return tab1_content, no_update
        elif pathname == "/dashboard/view2a":
            return tab2_content_orgs, no_update
        elif pathname == "/dashboard/view2b":
            return tab2_content_ips, no_update
        elif pathname == "/dashboard/view3":
            return tab3_content, no_update
        elif pathname == "/dashboard/view4":
            return tab4_content, no_update
        elif pathname == "/dashboard/report":
            return tab5_content, no_update

        return tab1_content, "/dashboard/view1"

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


        
        
        
        
        
