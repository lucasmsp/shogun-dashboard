from dash import html, dcc, dash_table, callback_context, ctx, no_update
from dash.dependencies import Output, Input, State
import dash_bootstrap_components as dbc
import dash_ag_grid as dag

import itertools
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import re

import project.base as base


INPUT_DATA_V2 = '2'

def register_layout_query(dm):
    # visualização 2a
    filters_2a = dbc.Row([
        dbc.Col(children=[
            html.Center([
                dcc.Input(
                    id="search-bar-ip",
                    type="search",
                    placeholder="Search by IP...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),

            html.Center([
                dcc.Input(
                    id="search-bar-org",
                    type="search",
                    placeholder="Search by Organization...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),
            html.Label(
                'EPSS range',
                style={
                    "marginLeft": "30px",
                    "marginBottom": "10px",
                }
            ),
            dcc.RangeSlider(
                id="epss-range-slider",
                min=0,
                max=1,
                step=0.01,
                marks={
                    0.0: '0.0',
                    0.2: '0.2',
                    0.4: '0.4',
                    0.6: '0.6',
                    0.8: '0.8',
                    1.0: '1.0',
                },
                value=[0.6, 1.0],
                tooltip={
                    'placement': 'top',
                    'always_visible': True,
                },
                allowCross=False,
            ),
        ], style={'padding': 10, 'flex': 1}),
        dbc.Col(children=[

            html.Center([
                dcc.Input(
                    id="search-bar-cpe-product",
                    type="search",
                    placeholder="Search by product name...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),
            html.Center([
                dcc.Input(
                    id="search-bar-cpe-version",
                    type="search",
                    placeholder="Search by product version...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),
            html.Label('CVSS rank'),
            dcc.Checklist(
                id="cvss-rank-checklist",
                options=[
                    {'label': 'Low', 'value': 'low'},
                    {'label': 'Medium', 'value': 'medium'},
                    {'label': 'High', 'value': 'high'},
                    {'label': 'Critical', 'value': 'critical'}
                ],
                labelStyle={
                    "fontSize": "20px"
                },
                inputStyle={
                    "margin": "10px",
                    "transition": "background-color 0.3s ease-in-out 0.1s",
                },
                inline=True,
            ),

            html.Br(),
        ], style={'padding': 10, 'flex': 1})
    ])

    filters_2b = html.Div([
        html.Div(children=[
            html.Center([
                dcc.Input(
                    id="search-bar-org-2b",
                    type="search",
                    placeholder="Search by organization...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),
            html.Center([
                dcc.Input(
                    id="search-bar-ip-2b",
                    type="search",
                    placeholder="Search by IP...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),
        ], style={'padding': 10, 'flex': 1}),

        html.Div(children=[

            html.Center([
                dcc.Input(
                    id="search-bar-cpe-2b",
                    type="search",
                    placeholder="Search by CPE...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),

            html.Center([
                dcc.Input(
                    id="search-bar-cve-2b",
                    type="search",
                    placeholder="Search by CVE...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),
        ], style={'padding': 10, 'flex': 1})
    ], style={'display': 'flex', 'flexDirection': 'row'})

    tab1_content = [
        html.H2(children="List of vulnerable products for each org/IP", className='wrapper'),
        filters_2a,
        dbc.Row(
            dag.AgGrid(
                id="query-2a-grid",
                columnDefs=[
                    {"field": 'org_clean', "headerName": 'Organization (clean)'},
                    {"field": 'ip_str', "headerName": 'IP', },
                    {"field": 'epss', "headerName": 'EPSS', "tooltipField": "epss_rank"},
                    {"field": 'cvss_rank', "headerName": 'CVSS Rank', "tooltipField": "cvss_rank"},
                    {
                        "field": 'cpe_product', 
                        "headerName": 'Product name', 
                        "tooltipField": "cve_id"
                    },
                ],
                defaultColDef={"flex": 1},
                columnSize="responsiveSizeToFit",
                columnSizeOptions= {"skipHeader": False},
                dashGridOptions={
                    'tooltipInteraction': True,
                    'tooltipShowDelay': 10, 
                    'tooltipHideDelay': 10000
                }
            )
        ),

        html.Br(),
        dbc.Row(
            [
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-color-2a",
                        options=[
                            {'label': 'EPSS', 'value': 'epss_rank'},
                            {'label': 'CVE', 'value': 'cve_id'},
                        ],
                        placeholder="Group by...",
                        style={
                            "width": "90%",
                            "margin": "15px",
                        },
                        value='epss_rank'
                    ),
                ),
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-type-2a",
                        options=[
                            {'label': 'Bars', 'value': 'Bars'},
                            {'label': 'PDF/CDF', 'value': 'CDF'},
                        ],
                        placeholder="Type of graph...",
                        style={
                            "width": "90%",
                            "margin": "15px",
                        },
                        value='Bars'
                    ),
                )
            ]
        ),
        dcc.Graph(
            id="query-2a-graph",
            config={
                'displayModeBar': False,
                'scrollZoom': False
            },
            style={
                "display": "flex",
            }
        )
    ]

    tab2_content = [
        html.H2(children="Highest EPSS for each org/IP", className='wrapper'),
        filters_2b,
        dbc.Row(
            dag.AgGrid(
                id="query-2b-grid",
                columnDefs=[
                    {"field": 'org_clean', "headerName": 'Organization'},
                    {"field": 'epss', "headerName": 'EPSS (major)', },
                ],
                defaultColDef={"flex": 1},
                columnSize="responsiveSizeToFit",
                columnSizeOptions= {"skipHeader": False},
                dashGridOptions={"rowSelection": "single", "animateRows": False}
            )
        ),
        dbc.Modal(
            [
                dbc.ModalHeader(
                    dcc.Tabs(
                        id="tabs-modal-2b",
                        children=[
                            dcc.Tab(
                                label="IP list", 
                                value="ip_str", 
                                style={'padding': '6px', 'display': 'flex', 'width': '90px', 'justify-content': 'center'},
                                selected_style={'padding': '6px', 'display': 'flex', 'width': '100px', 'justify-content': 'center'},
                            ),
                            dcc.Tab(
                                label="CVE list", 
                                value="cve_list", 
                                style={'padding': '6px', 'display': 'flex', 'width': '90px', 'justify-content': 'center'},
                                selected_style={'padding': '6px', 'display': 'flex', 'width': '100px', 'justify-content': 'center'},
                            ),
                            dcc.Tab(
                                label="CPE list",
                                value="cpe_list",
                                style={'padding': '6px', 'display': 'flex', 'width': '90px', 'justify-content': 'center'},
                                selected_style={'padding': '6px', 'display': 'flex', 'width': '100px', 'justify-content': 'center'},
                            ),
                        ],
                        value="ip_list",
                        style={'height': '44px'}
                    ),
                    id="header-modal-2b",
                ),
                dbc.ModalBody(id="body-modal-2b"),
            ],
            id="modal-info-2b",
            is_open=False,
            scrollable=True
        ),

        html.Br(),

        dbc.Row(
            [
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-type-2b",
                        options=[
                            {'label': 'Bars', 'value': 'Bars'},
                            {'label': 'PDF/CDF - Distribution of CVE by IPs', 'value': 'CDF'},
                        ],
                        placeholder="Type of graph...",
                        style={
                            "width": "90%",
                            "margin": "15px",
                        },
                        value="Bars"
                    ),
                )
            ]
        ),

        dcc.Graph(
            id="query-2b-graph",
            config={
                'displayModeBar': False,
                'scrollZoom': False
            }
        )
    ]


    q2 = [
        html.H1(children="View 2 - by organizations/IP", className='wrapper'),
        html.Br(),
        dbc.Tabs(
            [
                dbc.Tab(tab1_content, label="List of vulnerable products for each org/IP"),
                dbc.Tab(tab2_content, label="Highest EPSS for each org/IP"),
            ]
        ),
        dbc.Modal(
            [
                dbc.ModalHeader(
                    dcc.Tabs(
                        id="tabs-modal-2b",
                        children=[
                            dcc.Tab(
                                label="IP list", 
                                value="ip_str", 
                                style={'padding': '6px', 'display': 'flex', 'width': '90px', 'justify-content': 'center'},
                                selected_style={'padding': '6px', 'display': 'flex', 'width': '100px', 'justify-content': 'center'},
                            ),
                            dcc.Tab(
                                label="CVE list", 
                                value="cve_list", 
                                style={'padding': '6px', 'display': 'flex', 'width': '90px', 'justify-content': 'center'},
                                selected_style={'padding': '6px', 'display': 'flex', 'width': '100px', 'justify-content': 'center'},
                            ),
                            dcc.Tab(
                                label="CPE list",
                                value="cpe_list",
                                style={'padding': '6px', 'display': 'flex', 'width': '90px', 'justify-content': 'center'},
                                selected_style={'padding': '6px', 'display': 'flex', 'width': '100px', 'justify-content': 'center'},
                            ),
                        ],
                        value="ip_str",
                        style={'height': '44px'}
                    ),
                    id="header-modal-2b",
                ),
                dbc.ModalBody(id="body-modal-2b"),
            ],
            id="modal-info-2b",
            is_open=False,
            scrollable=True
        ),
    ]

    return q2



def register_callback_query(dm, app):

    @app.callback(
        Output('query-2a-grid', "rowData"),
        [
            Input('date-picker-single', 'value'),
            Input("search-bar-ip", 'value'),
            Input("search-bar-org", 'value'),
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("search-bar-cpe-product", 'value'),
            Input("search-bar-cpe-version", 'value'), 
            Input("general-tabs", "active_tab"),
        ], prevent_initial_call=True
    )
    def update_grid2a(date_value, ip_query, org_query, epss_query, cvss_query, product_query, cpe_version_query, active_tab):
        if "tab-1" != active_tab:
            return [{}]
        print("[INFO] query 2 - update_table2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return [{}]
        if ip_query:
            df = df[df['ip_str'].str.contains(ip_query, case=False)]

        if org_query:
            df = df[df['org_clean'].str.contains(org_query, case=False)]

        if epss_query:
            epss_min, epss_max = epss_query
            df = df[(df['epss'] >= epss_min) & (df['epss'] <= epss_max)]

        if cvss_query:
            df = df[df['cvss_rank'].isin(cvss_query)]

        if product_query:
            df = df[df['cpe_product'].str.contains(product_query, case=False)]

        if cpe_version_query:
            df = df[df['cpe_version'].str.contains(cpe_version_query)]

        df = df.sort_values(by=['epss'], ascending=True)


        return df.to_dict('records')


    @app.callback(
        Output('query-2a-graph', 'figure'),
        [
            Input('date-picker-single', 'value'),
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("search-bar-cpe-version", 'value'),
            Input("dropdown-color-2a", 'value'),
            Input("dropdown-type-2a", 'value'), 
            Input("general-tabs", "active_tab"),
        ], prevent_initial_call=True
    )
    def update_graph2a(date_value, epss_query, cvss_query, cpe_version_query, color, type, active_tab):
        if "tab-1" != active_tab:
            return {}
        print("[INFO] query 2 - update_graph2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return {}

        if epss_query:
            epss_min, epss_max = epss_query
            df = df[(df['epss'] >= epss_min) & (df['epss'] <= epss_max)]

        if cvss_query:
            df = df[df['cvss_rank'].isin(cvss_query)]

        if cpe_version_query:
            df = df[df['cpe_version'].str.contains(cpe_version_query)]

        
        if type == "CDF":
            stats_df = df \
                .groupby('epss') \
                ['epss'] \
                .agg('count') \
                .pipe(pd.DataFrame) \
                .rename(columns = {'epss': 'frequency'})

            # PDF
            stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])

            # CDF
            stats_df['cdf'] = stats_df['pdf'].cumsum()
            stats_df = stats_df.reset_index()

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['pdf'], mode='lines', name='PDF'))
            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['cdf'], mode='lines', name='CDF'))
            fig.update_layout(title='PDF and CDF',
                            xaxis_title='Value',
                            yaxis_title='Probability',
                            showlegend=True)
            return fig
        
        else:      
            df = df.sort_values(by=['cvss_rank'], ascending=True)
            severity_mapping = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4
            }

            cvss_counts = df['cvss_rank'].value_counts()
            df['severity'] = df['cvss_rank'].map(severity_mapping)


            fig = go.Figure()

            fig.add_trace(go.Bar(x=cvss_counts.index, y=cvss_counts.values, name='CVSS Rank'))

            fig.update_layout(
                # title='Distribution of CVSS Rank',
                xaxis=dict(title='CVSS Rank'),
                yaxis=dict(title='Number of registers'))

            if color:
                grouped_df = df.groupby(['cvss_rank', 'severity', color.lower()])
                aggregated_df = grouped_df.size().to_frame(name='count')
                aggregated_df = aggregated_df.reset_index()
                aggregated_df = aggregated_df.sort_values('severity')
                fig = px.bar(aggregated_df, x='cvss_rank', y="count", color=color.lower())
                fig.update_layout(
                    # title='Distribution of CVSS Rank',
                    xaxis=dict(title='CVSS Rank'),
                    yaxis=dict(title='Number of registers'))
            return fig
        
    def contar_virgulas(texto):
        return len(re.findall(r";", texto)) + 1
    
    @app.callback(
        
        Output("query-2b-grid", "rowData"),
        [
            Input('date-picker-single', 'value'),
            Input("search-bar-org-2b", 'value'),
            Input("search-bar-ip-2b", 'value'),
            Input("search-bar-cpe-2b", 'value'),
            Input("search-bar-cve-2b", 'value'), 
            Input("general-tabs", "active_tab"),
        ], prevent_initial_call=True
    )
    def update_grid2b(date_value, org_query, ip_query, cpe_query, cve_query, active_tab):
        if "tab-1" != active_tab:
            return [{}]

        print("[INFO] query 2 - update_table2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return [{}]
        aggregated_df = df.groupby('org_clean').agg({
            'ip_str': lambda x: list(x),
            'cve_id': lambda x: list(x),
            'cpe_product': lambda x: list(x),
            'epss': 'max'
        }).reset_index()

        

        if org_query:
            aggregated_df = aggregated_df[aggregated_df['org_clean'].str.contains(org_query, case=False)]
        if ip_query:
            aggregated_df = aggregated_df[aggregated_df['ip_str'].str.contains(ip_query, case=False)]
        if cpe_query:
            aggregated_df = aggregated_df[aggregated_df['cpe_product'].str.contains(cpe_query, case=False)]
        if cve_query:
            aggregated_df = aggregated_df[aggregated_df['cve_id'].str.contains(cve_query, case=False)]


        return aggregated_df.to_dict('records')
    
    @app.callback(
        [   
            Output("modal-info-2b", "is_open"),
            Output("body-modal-2b", "children"),
        ],
        [
            Input("query-2b-grid", "selectedRows"),
            Input("tabs-modal-2b", "value")
        ]
    )
    def manage_modals_2b(selection, tab):
        if selection:
            text = dbc.ListGroup(
                [dbc.ListGroupItem(i) for i in selection[0]["ip_str"]]
            )
            if tab == "ip_list":
                text = dbc.ListGroup(
                    [dbc.ListGroupItem(i) for i in selection[0]["ip_str"]]
                )
            elif tab == "cve_list":
                text = dbc.ListGroup(
                    [dbc.ListGroupItem(i) for i in selection[0]["cve_id"]]
                ) 
            elif tab == "cpe_list":
                text = dbc.ListGroup(
                    [dbc.ListGroupItem(i) for i in selection[0]["cpe_product"]]
                )
            return True, text
        return False, dbc.ListGroup(
                    [dbc.ListGroupItem(i) for i in [""]]
                )

    @app.callback(
        Output('query-2b-graph', 'figure'),
        Input('date-picker-single', 'value'),
        Input("search-bar-org-2b", 'value'),
        Input("dropdown-type-2b", 'value'), 
        Input("general-tabs", "active_tab"),
        prevent_initial_call=True
    )
    def update_graph2b(date_value, org_query, type, active_tab):
        if "tab-1" != active_tab:
            return {}
        print("[INFO] query 2 - update_graph2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return {}
        aggregated_df = df.groupby('org_clean').agg({
            'ip_str': lambda x: list(x),
            'cve_id': lambda x: list(x),
            'cpe_product': lambda x: list(x),
            'epss': 'max'
        }).reset_index()
        aggregated_df["n_ips"] = aggregated_df["ip_str"].apply(len)
        aggregated_df = aggregated_df.sort_values("n_ips")

        if type == "CDF":
            stats_df = aggregated_df \
                .groupby('n_ips') \
                ['n_ips'] \
                .agg('count') \
                .pipe(pd.DataFrame) \
                .rename(columns = {'n_ips': 'frequency'})

            # PDF
            stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])

            # CDF
            stats_df['cdf'] = stats_df['pdf'].cumsum()
            stats_df = stats_df.reset_index()
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=stats_df['n_ips'], y=stats_df['pdf'], mode='lines', name='PDF'))
            fig.add_trace(go.Scatter(x=stats_df['n_ips'], y=stats_df['cdf'], mode='lines', name='CDF'))

            fig.update_layout(title='PDF/CDF - Distribution of CVE by IPs',
                            xaxis_title='Number of IPs (< 100)',
                            yaxis_title='Probability',
                            showlegend=True,
                            xaxis_range=[1,100])
            return fig
        else:
            ips_cont = aggregated_df['n_ips'].value_counts()
            if org_query:
                aggregated_df = aggregated_df[aggregated_df['org_clean'].str.contains(org_query, case=False)]
                
            fig = go.Figure()

            fig.add_trace(go.Bar(x=ips_cont.index, y=ips_cont.values, name='Number of IPs'))

            fig.update_layout(title='Bar plot - Distribution of CVE by IPs',
                    xaxis=dict(title='Number of IPs (< 100)'),
                    yaxis=dict(title='Number of organizations'),
                    xaxis_range=[0,100])
            return fig