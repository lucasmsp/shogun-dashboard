from dash import html, dcc, html, Input, Output
import dash_ag_grid as dag

import dash_bootstrap_components as dbc

import re

from flask_login import current_user

TAB_VIEW = "tab-4"

def register_layout_query(filter_modal={}):

    aggrid = dag.AgGrid(
                id="query-5-ag",
                rowData = [{"data": "Processing...", "ip": "0", "port": 0, "city": "", "os": "",
                            "org_clean": "", "hostnames": "", "domains": "", "score": 0, "meta_id": ""
                            }],
                persistence=True,
                filterModel=filter_modal,
                columnDefs=[
                    {"field": 'servers', "headerName": 'SERVICE', "cellRenderer": "markdown",
                      'width': 300, 'maxWidth': 500, "resizable": True, },
                    {"field": 'ip', "headerName": 'IP', "cellRenderer": "IPLink", 
                     "tooltipValueGetter": {"function": "'Click on the cell for more details'"}, 
                     'width': 150, 'maxWidth': 150, "resizable": False
                     },
                    {"field": 'port', "headerName": 'PORT', "resizable": False, 'width': 100, 'maxWidth': 100},
                    {"field": 'city', "headerName": "CITY", 'width': 150, "wrapText": True},
                    {"field": 'os', "headerName": "OS", 'width': 80, "wrapText": True},
                    {"field": 'asn', "headerName": "ASN",  'maxWidth': 120, "wrapText": True},
                    {"field": 'org_clean', "headerName": "ORGANIZATION", "wrapText": True},
                    {"field": 'hostnames', "headerName": "HOSTNAMES", "wrapText": True, "cellRenderer": "markdown"},
                    {"field": 'domains', "headerName": "DOMAINS", "wrapText": True, "cellRenderer": "markdown"},
                    {"field": 'score', "headerName": "SCORE", "resizable": False, 'width': 100, 'maxWidth': 100, "valueFormatter": {"function": """d3.format(",.4f")(params.value)"""}},
                    {"field": 'meta_id',"headerName": 'VOTE',  "cellRenderer": "launchBtn", "resizable": False,  'width': 170, 'maxWidth': 170, "filter": False, 'sortable': False},
                ],
                defaultColDef={"flex": 1, "filter": True},
                columnSize="sizeToFit",
                columnSizeOptions={"skipHeader": False},
                dashGridOptions={
                    "pagination": True,
                    'tooltipInteraction': True,
                    'tooltipShowDelay': 10,
                    'tooltipHideDelay': 1000,
                    "rowHeight": 120,
                    'animateRows': False,
                    "suppressColumnMoveAnimation": True,
                    "paginationPageSize": 20
                },
                style={"height": "1000px"},
                className="ag-theme-alpine compact"
            )

    elements = [
        html.H2(
            children=("Shodan's banners about IPs with vulnerabilities in Brazil. "
                      "Using this interface, users can filter banners by each column, "
                      "ranking its vulnerabilities and clicking on IP column to check details."
                      ),
            style={'fontSize': '20px', 'padding': 20}
        ),
        dbc.Row(dcc.Loading([aggrid]))
    ]

    tab5_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=elements)], className="wrapper_table",
                     style={"width": "100%", "height": "100%"}),
        ),
        className="mt-3",
        id="tab5_content"
    )

    return tab5_content

def register_callback_query(dm, app):

    @app.callback(
        Output('query-5-ag', "rowData"),
        [
            Input('date-picker-single', 'value')
        ]
    )
    def update_table5(date_value):

        print("[INFO][query5] - update_table5: ", date_value)

        df = dm.get_report_dataset(
            date_value,
            columns=["data", "ip", "port", "city", "os", "org_clean", "hostnames", "domains",
                     "meta_id", "vulns_epss", "asn", 'servers'],
            sort_by='score',
            ascending=False,
            compute_score=True,
            user_id=current_user.id,
            for_each=False
        )

        if df.empty:
            return [{}]

        return df.to_dict('records')
