import itertools
from dash import html, dcc, dash_table
import dash_ag_grid as dag

from dash import Dash, dcc, html, Input, Output

import dash_bootstrap_components as dbc

import re

TAB_VIEW = "tab-4"

def register_layout_query(dm):

    layout = [
        dbc.Row(
            dag.AgGrid(
                id="query-5-ag",
                columnDefs=[
                    {"field": 'data', "headerName": 'SERVICE', "cellRenderer": "markdown",
                      'width': 300, 'maxWidth': 300, "resizable": False, "wrapText": True, "autoHeight": True},
                    {"field": 'ip_str', "headerName": 'IP', "cellRenderer": "IPLink", 
                     "tooltipValueGetter": {"function": "'Click on the cell for more details'"}, 
                     'width': 150, 'maxWidth': 150, "resizable": False
                     },
                    {"field": 'port', "headerName": 'PORT', 
                     "cellRenderer": "Button", "cellRendererParams": {"className": "btn btn-primary"},  
                     "resizable": False, 'width': 100, 'maxWidth': 100},
                    {"field": 'city', "headerName": "CITY", 'width': 150, "wrapText": True},
                    {"field": 'os', "headerName": "OS", 'width': 80, "wrapText": True},
                    {"field": 'org', "headerName": "ORGANIZATION", "wrapText": True},
                    {"field": 'hostnames', "headerName": "HOSTNAMES", "wrapText": True, "cellRenderer": "markdown"},
                    {"field": 'domains', "headerName": "DOMAINS", "wrapText": True, "cellRenderer": "markdown"},
                    {"field": 'score', "headerName": "SCORE", "resizable": False, 'width': 100, 'maxWidth': 100, "valueFormatter": {"function": """d3.format(",.4f")(params.value)"""}},
                    {"field": 'meta_id',"headerName": 'VOTE',  "cellRenderer": "launchBtn", "resizable": False,  'width': 170, 'maxWidth': 170, "filter": False, 'sortable': False},
                ],
                defaultColDef={"flex": 1, "filter": True},
                columnSize="responsiveSizeToFit",
                columnSizeOptions={"skipHeader": False},
                dashGridOptions={
                    "pagination": True,
                    'tooltipInteraction': True,
                    'tooltipShowDelay': 10,
                    'tooltipHideDelay': 1000,
                    "rowHeight": 50,
                    'animateRows': False,
                    "suppressColumnMoveAnimation": True,
                    "paginationPageSize": 20
                },
                style={"height": "1000px"},
                className="ag-theme-alpine compact"
            )
        ),

    ]

    q5 = [
        html.H2(
            children=("Shodan's banners about IPs with vulnerabilities in Brazil. "
                      "Using this interface, users can filter banners by each column, "
                      "ranking its vulnerabilities and clicking on IP column to check details."
                      ),
            style={'fontSize': '20px', 'padding': 20}
        ),

        dbc.Tab(layout, label="Table")
    ]

    return q5


# register all the callbacks in one place
def register_callback_query(dm, app):

    @app.callback(
        Output('query-5-ag', "rowData"),
        [
            Input('date-picker-single', 'value'),
            Input("general-tabs", "active_tab")
        ], prevent_initial_call=True
    )
    def update_table5(date_value, active_tab=None):

        if TAB_VIEW != active_tab:
            return [{}]
        print("[INFO][query5] - update_table5: ", date_value)

        df = dm.get_report_dataset_new(
                date_value,
                columns=["data", "ip_str", "port", "city", "os", "org", "hostnames", "domains", "meta_id", "vulns_scores"], 
                sort_by='score',
                ascending=False
            )

        if df.empty:
            return [{}]
        
        def format_data(raw):
            if not raw:
                raw = ""

            space_index = raw.find(' ')
            if space_index != -1:
                truncate_data = raw[0:space_index]
            else:
                truncate_data = raw
            
            text = f"**{truncate_data}**"

            match1 = re.search('Server: [^\r\n]+', raw)
            if match1:
                server = match1.group()
                text += f"\n\n{server}"


            match2 = re.search('Date: [^\r\n]+', raw)
            if match2:
                date_match = match2.group()
                text += f"\n\n{date_match}"

            return text

        df['data'] = df.apply(lambda row: format_data(row['data']), axis=1)
        df['hostnames']= df['hostnames'].fillna('')
        df['domains']= df['domains'].fillna('')
        df['hostnames'] = ['\n\n'.join(map(str, l)) for l in df['hostnames']]
        df['domains'] = ['\n\n'.join(map(str, l)) for l in df['domains']]


        return df.to_dict('records')
