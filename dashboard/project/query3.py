from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output

import plotly.express as px
import plotly.graph_objs as go
import plotly.figure_factory as ff

import pandas as pd
import json

import project.base as base

INPUT_DATA = '3'

def dash_components():
    components_1 = html.Div([
        html.Div(children=[
            html.Center([
                dcc.Input(
                    id="search-bar-cve",
                    type="search",
                    placeholder="Search by CVE...",
                    style={
                        "width": "100%",
                        "margin": "15px"
                    }
                )
            ]),

            dcc.Dropdown(
                placeholder="CVSS version",
                id='dropdown-cvss-version',
                options=[
                    {'label': '3.1', 'value': '3.1'},
                    {'label': '3.0', 'value': '3.0'},
                    {'label': '2.1', 'value': '2.1'},
                ],
                multi=False,
                style={
                    "width": "100%",
                    "margin": "7px",
                },
            ),

            html.Label(
                children='Choose the CVSS range',
                style={
                    "margin-left": "30px",
                    "margin-bottom": "10px",
                }
            ),
            dcc.RangeSlider(
                id='cvss-range-slider',
                min=0,
                max=10,
                count=1,
                value=[0, 10],
                tooltip={
                    'placement': 'top',
                    'always_visible': True,
                },
                allowCross=False,
            ),

        ], style={'padding': 10, 'flex': 1}),

        html.Div(children=[
            html.Center([
                dcc.Input(
                    id='search-bar-org',
                    type="search",
                    placeholder="Org filter expression ('>', '<', '=','>=', '<=') e.g., '> 30'",
                    style={
                        "width": "100%",
                        "margin": "15px"
                    }
                )
            ]),

            html.Center([
                dcc.Input(
                    id='search-bar-ip',
                    type="search",
                    placeholder="IP filter expression ('>', '<', '=','>=', '<=') e.g., '> 30'",
                    style={
                        "width": "100%",
                        "margin": "15px"
                    }
                )
            ]),

            html.Label(
                children='Choose the EPSS range',
                style={
                    "margin-left": "30px",
                }
            ),
            dcc.RangeSlider(
                id='epss-range-slider',
                min=0,
                max=1,
                step=0.1,
                marks={
                    0.0: '0.0',
                    0.2: '0.2',
                    0.4: '0.4',
                    0.6: '0.6',
                    0.8: '0.8',
                    1.0: '1.0',
                },
                value=[0.1, 1.0],
                tooltip={
                    'placement': 'top',
                    'always_visible': True,
                },
                allowCross=False,
            ),
        ],
            style={'padding': 10, 'flex': 1})
    ],
        style={'display': 'flex', 'flexDirection': 'row'}
    )
    return components_1


#constructs the layout for View 3
def register_layout_query(dm):
    component_1 = dash_components()
    # visualização 3
    q3 = [
        dbc.Row(
            children=[
                html.H1(
                    children="View 3 - More details by CVE",
                    style={'text-align': 'center'}
                ),
                html.H2(
                    children="This visualization allows the analysis of the distribution of CVEs "
                             "in relation to IPs and organizations accessible on the Internet",
                    style={'font-size': '20px'}
                ),

                component_1,
                dbc.Row(
                    dash_table.DataTable(
                        id='query-3-table',
                        columns=[
                            {"name": "CVE", "id": "cve_id", "selectable": True},
                            {"name": "CVSS (CVSS version)", "id": "cvss_and_cvssv", "selectable": True},
                            {"name": "CVSS Rank", "id": "cvss_rank", "selectable": True},
                            {"name": "EPSS", "id": "epss", "selectable": True},  # TODO {mudar o valor para epss}
                            {"name": "EPSS Rank", "id": "epss_rank", "selectable": True},
                            {"name": "# IPs", "id": "n_ips", "selectable": True},
                            {"name": "# Organizations", "id": "n_orgs", "selectable": True},
                        ],
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        page_current=0,
                        page_size=15,
                        style_data={
                            'whiteSpace': 'normal',
                            'max-height': '15px',
                            'min-height': '15px',
                            'height': '15px'
                        }
                    ),
                    style={'margin-top': '32px'}
                ),

                html.Div(style={'height': '50px'}),

                html.H4(children="Choose the type of chart", style={'text-align': 'Left'}),
                dbc.Row(
                    dcc.Dropdown(
                        id='graph-type',
                        options=[
                            {'label': 'Scatter plot - EPSS by CVSS Score', 'value': 'epss_cvss'},
                            {'label': 'Confusion Matrix - EPSS Rank by CVSS Rank', 'value': 'epss_rank_cvss_rank'},
                            {'label': 'Line plot - # IPS by CVSS', 'value': 'ips_cvss'},
                            {'label': 'Line plot - # IPs by EPSS', 'value': 'ips_epss'},
                            {'label': 'Line plot - # Organizations by CVSS', 'value': 'orgs_cvss'},
                            {'label': "Line plot - # Organizations by EPSS", 'value': 'orgs_epss'},                            
                        ],
                        value='Scatter plot - EPSS by CVSS Score'
                    ),
                    style={'margin-top': '32px'}
                ),
                html.Div(id='datable-interactivity-container'),
            ]
        ),
    ]

    return q3


def find_expression(string):
    list_expressions = ['>=', '<=', '!=']
    for i in list_expressions:
        index = string.find(i)

        if index != -1:
            return i



# register all the callbacks in one place
def register_callback_query(dm, app):
    @app.callback(
        Output('query-3-table', "data"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by"),
        Input('search-bar-cve', 'value'),
        Input('dropdown-cvss-version', 'value'),
        Input('cvss-range-slider', 'value'),
        Input('epss-range-slider', 'value'),
        Input('search-bar-org', 'value'),
        Input('search-bar-ip', 'value')
    )
    def update_table3(date_value, sort_by, cve_query, dropdown_query_cvss, cvss_range_query,
                      epss_range_query, org_query, ip_query):
        print("[INFO] query 3 - update_table3: ", date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA)

        df['cvss_and_cvssv'] = df['cvss_score'].astype(str) + ' (v ' + df['cvss_version'].astype(str) + ')'
        #df['cvss_version'] = df['cvss_version'].astype(float)
        #df['cvss_score'] = df['cvss_score'].astype(float)

        if len(sort_by):
            df = df.sort_values(
                [col['column_id'] for col in sort_by],
                ascending=[
                    col['direction'] == 'asc'
                    for col in sort_by
                ],
                inplace=False
            )

        if cve_query:
            df = df[df['cve_id'].str.contains(cve_query, case=False)]

        if dropdown_query_cvss:
            drop = str(dropdown_query_cvss)
            value = float(drop)
            df = df[df['cvss_version'] == value]

        if cvss_range_query:
            df = df[(df['cvss_score'] >= cvss_range_query[0]) & (df['cvss_score'] <= cvss_range_query[1])]

        if epss_range_query:
            df = df[(df['epss'] >= cvss_range_query[0]) & (df['epss'] <= cvss_range_query[1])]

        if org_query:
            op = str(org_query)
            op = op.replace(" ", "")
            result_expression = find_expression(op)

            if result_expression in ['>=', '<=', '!=']:
                info = op.split('=')
                value = int(info[1])
                if result_expression == ">=":
                    df = df[df['n_orgs'] >= value]

                elif result_expression == '<=':
                    df = df[df['n_orgs'] <= value]

                elif result_expression == '!=':
                    df = df[df['n_orgs'] != value]

            else:
                operator = op[0]
                value = op[1:].strip()
                value = int(value)
                if operator == '=':
                    df = df[df['n_orgs'] == value]
                elif operator == '>':
                    df = df[df['n_orgs'] > value]
                elif operator == '<':
                    df = df[df['n_orgs'] < value]

        if ip_query:
            op = str(ip_query)
            op = op.replace(" ", "")
            result_expression = find_expression(op)

            if result_expression in ['>=', '<=', '!=']:
                info = op.split('=')
                value = int(info[1])
                if result_expression == ">=":
                    df = df[df['n_ips'] >= value]

                elif result_expression == '<=':
                    df = df[df['n_ips'] <= value]

                elif result_expression == '!=':
                    df = df[df['n_ips'] != value]

            else:
                operator = op[0]
                value = op[1:].strip()
                value = int(value)
                if operator == '=':
                    df = df[df['n_ips'] == value]
                elif operator == '>':
                    df = df[df['n_ips'] > value]
                elif operator == '<':
                    df = df[df['n_ips'] < value]

        return df.to_dict('records')

    @app.callback(
        Output('query-3-table', "style_data_conditional"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by")
    )
    def update_styles(date_value, sort_by):
        print("[INFO] query 3 - update_styles: ", date_value)
        return [{
            'if': {'column_id': i['column_id']},
            'background_color': 'white'
        } for i in sort_by]

    @app.callback(
        Output('datable-interactivity-container', "children"),
        Input('date-picker-single', 'date'),
        Input('graph-type', 'value')
    )
    def update_graphs(date_value, value):
        print("[INFO] update_graphs: ", date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        graphs = []
        if value == "epss_cvss":
            fig = px.scatter(df, x=df["cvss_score"], y=df['epss'], title="Scatter plot - EPSS by CVSS score", color='epss_rank')
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="EPSS",
                # xaxis=dict(showticklabels=False),
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            graphs.append(
                dcc.Graph(
                    id=value,
                    figure=fig
                ))
        elif value == "epss_rank_cvss_rank":
            z = df.groupby(["cvss_rank", "epss_rank"]).count()\
                .reset_index()\
                .pivot(index="cvss_rank", columns="epss_rank", values=["cve_id"])\
                .fillna(0)\
                .reset_index()
            z.columns = ['epss_rank', '< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']

            severity_mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
            }
            z['severity'] = z['epss_rank'].map(severity_mapping)
            z = z.sort_values(by='severity', ascending=True)

            x = ["low", "medium", "high", "critical"]
            y = ['< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']
            z = z[y].T.values.tolist()
            z_text = [[str(y) for y in x] for x in z]
            
            fig = ff.create_annotated_heatmap(z, x=x, y=y, annotation_text=z_text, colorscale='Viridis') 
            fig['data'][0]['showscale'] = True

            fig.update_layout(
                height=600,
                width=600,
                title_text='Confusion Matrix - EPSS Rank by CVSS Rank',
                xaxis_title="CVSS Rank",
                yaxis_title="EPSS Rank",
                xaxis={'side': 'bottom'},
            )

            graphs.append(
                dcc.Graph(
                    id=value,
                    figure=fig
                ))

        elif value == "ips_cvss":
            df = df.groupby("cvss_score").sum("n_ips").reset_index()
            fig = px.line(df, x=df['cvss_score'], y=df['n_ips'], title="Line plot - # IPs by CVSS")
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="# IPs",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            graphs.append(
                dcc.Graph(
                    id=value,
                    figure=fig
                ))

        elif value == "orgs_cvss":
            df = df.groupby("cvss_score").sum("n_orgs").reset_index()
            fig = px.line(df, x=df['cvss_score'], y=df['n_orgs'], title="Line plot - # Organizations by CVSS")
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="# Organizations",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            graphs.append(
                dcc.Graph(
                    id=value,
                    figure=fig
                ))
        elif value == "orgs_epss":
            df = df.groupby("epss").sum("n_orgs").reset_index()
            fig = px.line(df, x=df['epss'], y=df['n_orgs'], title="Line plot - # Organizations by EPSS")
            fig.update_layout(
                xaxis_title="EPSS Score",
                yaxis_title="# Organizations",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    range=[0, 1.0]
                )
            )
            graphs.append(
                dcc.Graph(
                    id=value,
                    figure=fig
                ))

        elif value == "ips_epss":
            df = df.groupby("epss").sum("n_ips").reset_index()
            fig = px.line(df, x=df['epss'], y=df['n_ips'], title="Line plot - # IPs by EPSS")
            fig.update_layout(
                xaxis_title="# EPSS Score",
                yaxis_title="# IPs",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    range=[0, 1.0]
                )
            )
            graphs.append(
                dcc.Graph(
                    id=value,
                    figure=fig
                ))

        return graphs
