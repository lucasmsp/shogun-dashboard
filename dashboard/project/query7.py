from dash import html, dcc
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input

import plotly.express as px
import dash_ag_grid as dag


from project.auxiliar import gen_subgraphs, gen_columns_def

INPUT_DATA = '5'


def register_layout_query(filter_modal={}):
    columns, raw_data = gen_columns_def(['port', 'vulns_epss_max', 'vulns_cvss_score_max',
                                         'n_vulns_in_cisa', 'n_products'])

    for column in columns:
        column["resizable"] = False

    aggrid = dag.AgGrid(
        id='query-7-table',
        rowData=raw_data,
        columnDefs=columns,
        defaultColDef={"flex": 1, "filter": True},
        columnSize="responsiveSizeToFit",
        columnSizeOptions={"skipHeader": False},
        dashGridOptions={
            "rowSelection": "single",
            'tooltipInteraction': True,
            'tooltipShowDelay': 10,
            'tooltipHideDelay': 10000,
            "animateRows": False,
        }
    )

    elements = [
        html.H1(children="View 7 - Vulnerable Ports Summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
                dbc.Row(aggrid),
                dbc.Row(
                    dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
                dbc.Row([html.Div(id='query-7-graph', children=[])])
            ]
        )
    ]

    tab7_content = dbc.Card(
        dbc.CardBody(html.Div(children=[dbc.Row(children=elements)], className="wrapper")),
        className="mt-3",
        id="tab7_content"
    )

    return tab7_content


def register_callback_query(dm, app):
    @app.callback(
        Output('query-7-table', "rowData"),
        Input('date-picker-single', 'value')
    )
    def update_table1(date_value):
        print(f"[INFO][query7] update_table7: {date_value}")
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        return df.to_dict('records')