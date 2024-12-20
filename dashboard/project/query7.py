from dash import html, dcc, no_update
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input

import plotly.express as px
import dash_ag_grid as dag

from project.auxiliar import gen_subgraphs, gen_columns_def, header_mapping, gen_style_condition

INPUT_DATA = '5'


def register_layout_query(filter_modal={}):
    columns, raw_data = gen_columns_def(['port', 'vulns_epss_max',
                                         'vulns_epss_min', 'vulns_epss_avg',
                                         'vulns_cvss_score_max', 'vulns_cvss_score_min',
                                         'vulns_cvss_score_avg',
                                         'n_vulns', 'n_products', 'n_vulns_in_cisa',
                                         'n_vulns_cisa_knownRansomwareCampaignUse',
                                         ])

    for column in columns:
        column["resizable"] = False

    columns[1]["cellStyle"] = {
        "styleConditions": gen_style_condition("vulns_epss_max")
    }

    columns[2]["cellStyle"] = {
        "styleConditions": gen_style_condition("vulns_epss_min")
    }

    columns[3]["cellStyle"] = {
        "styleConditions": gen_style_condition("vulns_epss_avg")
    }

    columns[4]["cellStyle"] = {
        "styleConditions": gen_style_condition("vulns_cvss_score_max")
    }

    columns[5]["cellStyle"] = {
        "styleConditions": gen_style_condition("vulns_cvss_score_min")
    }

    columns[6]["cellStyle"] = {
        "styleConditions": gen_style_condition("vulns_cvss_score_avg")
    }

    columns[0]['width'] = 85
    columns[0]['minWidth'] = 85

    columns[1]['width'] = 125
    columns[1]['minWidth'] = 125

    columns[2]['width'] = 125
    columns[2]['minWidth'] = 125

    columns[3]['width'] = 125
    columns[3]['minWidth'] = 125

    columns[4]['width'] = 125
    columns[4]['minWidth'] = 125

    columns[5]['width'] = 125
    columns[5]['minWidth'] = 125

    columns[6]['width'] = 125
    columns[6]['minWidth'] = 125

    columns[7]['width'] = 100
    columns[7]['minWidth'] = 100

    columns[8]['width'] = 120
    columns[8]['minWidth'] = 120

    columns[9]['width'] = 145
    columns[9]['minWidth'] = 145

    columns = [
        columns[0],
        {
            "headerName": header_mapping['epss_info']['name'],
            "headerTooltip": header_mapping['epss_info']['description'],
            "children": columns[1:4],
        },
        {
            "headerName": header_mapping['cvss_info']['name'],
            "headerTooltip": header_mapping['cvss_info']['description'],
            "children": columns[4:7],
        },
        columns[7],
        columns[8],
        {
            "headerName": header_mapping['cisa_info']['name'],
            "headerTooltip": header_mapping['cisa_info']['description'],
            "children": columns[9:11],
        },
    ]

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

    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-7-table", "cellClicked"),
        Input('date-picker-single', 'value'),
        prevent_initial_call=True,
    )
    def filter_asn(cell,  date_value):
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if cell:
            if cell.get("colId", "") == "n_vulns":
                row_id = int(cell.get("rowId", 0))
                cve_list = df.at[row_id, "cve_list"]
                filter_opt = {
                    "query-3-ag": {
                        'vulns_cve_id': {
                            "filterType": "text",
                            "operator": "OR",
                            "conditions": [
                                {
                                    "filter": cve,
                                    "filterType": "text",
                                    "type": "equals"
                                } for cve in cve_list
                            ]
                        }
                    }
                }
                return "/dashboard/view3", filter_opt
        return no_update, no_update

