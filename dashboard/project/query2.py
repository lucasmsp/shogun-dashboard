from dash import html, dcc, dash_table, callback_context
from dash.dependencies import Output, Input, State
import dash_bootstrap_components as dbc

import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import re

import project.base as base


INPUT_DATA_V2a = '2a'
INPUT_DATA_V2b = '2b'

def register_layout_query(dm):
    # visualização 2a
    filters_2a = html.Div([
        html.Div(children=[
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
                    "margin-left": "30px",
                    "margin-bottom": "10px",
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
                value=[0.5, 0.7],
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
                    "font-size": "20px"
                },
                inputStyle={
                    "margin": "10px",
                    "transition": "background-color 0.3s ease-in-out 0.1s",
                },
                inline=True,
            ),

            html.Br(),
        ], style={'padding': 10, 'flex': 1})
    ], style={'display': 'flex', 'flexDirection': 'row'})

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

    q2 = [
        html.H1(children="View 2 - by organizations/IP", className='wrapper'),
        html.Br(),
        html.H2(children="Highest EPSS for each org/IP", className='wrapper'),
        filters_2a,
        dbc.Row(
            dash_table.DataTable(
                id='query-2a-table',
                columns=[
                    {"name": 'Organization (clean)', "id": 'org_clean'},
                    {"name": 'IP', "id": 'ip_str'},
                    # {"name": 'CVE', "id": 'cve_id'},
                    {"name": 'EPSS', "id": 'epss'},
                    # {"name": 'EPSS rank', "id": 'epss_rank'},
                    {"name": 'CVSS Rank', "id": 'cvss_rank'},
                    {"name": 'Product name', "id": 'cpe_product'},
                    # {"name": 'Product version', "id": 'cpe_version'},
                ],
                sort_action='custom',
                sort_mode='multi',
                sort_by=[],
                page_current=0,
                page_size=10,
                style_data={
                    'whiteSpace': 'normal',
                    'max-height': '15px',
                    'min-height': '15px',
                    'height': '15px'
                },
                tooltip_delay=0,
                tooltip_duration=None,
                style_cell={'textAlign': 'center'}
            ),
            style={'margin-top': '32px'},
        ),
        dbc.Popover([
            dbc.PopoverHeader("Título do Popover"),
            dbc.PopoverBody("Conteúdo do Popover"),
        ], id="popover"),
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
                        value='EPSS'
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
                'scrollZoom': True
            }
        ),
        html.Br(),

        html.H2(children="List of vulnerable products for each org/IP", className='wrapper'),
        filters_2b,
        dbc.Row(
            dash_table.DataTable(

                id='query-2b-table',
                columns=[
                    {"name": 'Organization', "id": 'org_clean'},
                    # {"name": 'IP list', "id": 'ip_list'},
                    {"name": 'EPSS (major)', "id": 'epss_major'},
                    # {"name": 'EPSS rank (major)', "id": 'epss_rank_major'},
                    # {"name": 'Product list', "id": 'cpe_list'},
                    # {"name": 'CVE list', "id": 'cve_list'}
                ],
                page_size=10,
                style_data={
                    'whiteSpace': 'normal',
                    # 'height': 'auto',
                    'max-height': '15px', 'min-height': '15px', 'height': '15px'
                },
                tooltip_delay=0,
                tooltip_duration=None,
                style_cell={'textAlign': 'center'},
                css=[{
                    'selector': '.dash-table-tooltip',
                    'rule': 'text-align: center; border: 1px solid;;'
                }],
            ),
            style={'margin-top': '32px'}

        ),
        html.Br(),

        dbc.Row(
            [
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-type-2b",
                        options=[
                            {'label': 'Bars', 'value': 'Bars'},
                            {'label': 'PDF/CDF', 'value': 'CDF'},
                        ],
                        placeholder="Type of graph...",
                        style={
                            "width": "90%",
                            "margin": "15px",
                        }
                    ),
                )
            ]
        ),

        dcc.Graph(
            id="query-2b-graph",
            config={
                'displayModeBar': False,
                'scrollZoom': True
            }
        )
    ]

    return q2



def register_callback_query(dm, app):
    @app.callback(
        Output('query-2a-table', "data"),
        Output('query-2a-table', "tooltip_data"),
        [
            Input('date-picker-single', 'date'),
            Input("search-bar-ip", 'value'),
            Input("search-bar-org", 'value'),
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("search-bar-cpe-product", 'value'),
            Input("search-bar-cpe-version", 'value'),
        ]
    )
    def update_table2a(date_value, ip_query, org_query, epss_query, cvss_query, product_query, cpe_version_query):
        print("[INFO] query 2 - update_table2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2a)
        if ip_query:
            df = df[df['ip_str'].str.contains(ip_query, case=False)]

        if org_query:
            df = df[df['org_clean'].str.contains(org_query, case=False)]

        if epss_query:
            epss_min, epss_max = epss_query
            df = df[(df['epss'] >= epss_min) & (df['epss'] <= epss_max)]

        if cvss_query:
            print(cvss_query)
            df = df[df['cvss_rank'].isin(cvss_query)]

        if product_query:
            df = df[df['cpe_product'].str.contains(product_query, case=False)]

        if cpe_version_query:
            df = df[df['cpe_version'].str.contains(cpe_version_query)]

        df = df.sort_values(by=['epss'], ascending=True)
        df_clean = df[['org_clean', 'ip_str', 'cvss_rank', 'epss', 'cpe_product']]
        tooltip_data = [
            {
                'ip_str': {
                    'value': "**CVE:**  " + str(row['cve_id']),
                    'type': 'markdown'
                },'cvss_rank': {
                    'value': "**CVSS:**  " + str(row['cvss_score']),
                    'type': 'markdown'
                },
                'epss': {
                    'value': "**EPSS Rank:**  " + str(row['epss_rank']),
                    'type': 'markdown'
                },
                'cpe_product': {
                    'value': "**Product Version:**  " + row['cpe_version'] + "  \n**CVE:**  " + row['cve_id'],
                    'type': 'markdown'
                }
            } for row in df.to_dict('records')
        ]


        return df_clean.to_dict('records'), tooltip_data

    @app.callback(
        Output('query-2a-graph', 'figure'),
        [
            Input('date-picker-single', 'date'),
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("search-bar-cpe-version", 'value'),
            Input("dropdown-color-2a", 'value'),
            Input("dropdown-type-2a", 'value'),
        ]
    )
    def update_graph2a(date_value, epss_query, cvss_query, cpe_version_query, color, type):
        
        print("[INFO] query 2 - update_graph2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2a)

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

            fig.update_layout(title='Distribution of CVSS Rank',
                    xaxis=dict(title='CVSS Rank'),
                    yaxis=dict(title='Number of registers'))

            if color:
                grouped_df = df.groupby(['cvss_rank', 'severity', color.lower()])
                aggregated_df = grouped_df.size().to_frame(name='count')
                aggregated_df = aggregated_df.reset_index()
                aggregated_df = aggregated_df.sort_values('severity')
                fig = px.bar(aggregated_df, x='cvss_rank', y="count", color=color.lower())
                fig.update_layout(title='Distribution of CVSS Rank',
                    xaxis=dict(title='CVSS Rank'),
                    yaxis=dict(title='Number of registers'))
            return fig
    
    # def contar_virgulas_str(texto):
    #     return str(len(re.findall(r",", texto)) + 1)
    
    def contar_virgulas(texto):
        return len(re.findall(r",", texto)) + 1
    
    def get_tooltip_info(row):
        cpe_list = row['cpe_list'].split(', ')
        cve_list = row['cve_list'].split(', ')
        string = ''
        while(cpe_list or cve_list):
            if cpe_list:
                string = string+  '| ' + cpe_list[0] + '  | '
                cpe_list.pop(0)
            else:
                string = string + '|  |  '
            if cve_list:
                string = string + cve_list[0] + '|  \n'
                cve_list.pop(0)
            else:
                string = string + ' |  \n'
        return string

    @app.callback(
        Output('query-2b-table', "data"),
        Output('query-2b-table', "tooltip_data"),
        [
            Input('date-picker-single', 'date'),
            Input("search-bar-org-2b", 'value'),
            Input("search-bar-ip-2b", 'value'),
            Input("search-bar-cpe-2b", 'value'),
            Input("search-bar-cve-2b", 'value'),
        ]
    )
    def update_table2b(date_value, org_query, ip_query, cpe_query, cve_query):
        # título

        print("[INFO] query 2 - update_table2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2b)

        if org_query:
            df = df[df['org_clean'].str.contains(org_query, case=False)]
        if ip_query:
            df = df[df['ip_list'].str.contains(ip_query, case=False)]
        if cpe_query:
            df = df[df['cpe_list'].str.contains(cpe_query, case=False)]
        if cve_query:
            df = df[df['cve_list'].str.contains(cve_query, case=False)]

        df_limpo = df[['org_clean', 'epss_major']]

        tooltip_data = [
            {
                'org_clean': {
                    'value': "| CPE list        | CVE list        |  \n" +
                             "| :-------------: | :-------------: |  \n" +
                             get_tooltip_info(row),
                    'type': 'markdown'
                },
                'epss_major': {
                    'value': "**IP list:**  \n" + "  \n".join(row['ip_list'].split(', ')),
                    'type': 'markdown'
                },
            } for row in df.to_dict('records')
        ]

        return df_limpo.to_dict('records'), tooltip_data

    
    @app.callback(
        Output('query-2b-graph', 'figure'),
        Input('date-picker-single', 'date'),
        Input("search-bar-org-2b", 'value'),
        Input("dropdown-type-2b", 'value'),
    )
    def update_graph2b(date_value, org_query, type):
        print("[INFO] query 2 - update_graph2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2b)

        df["n_ips"] = df["ip_list"].apply(contar_virgulas)
        df["n_ips_str"] = str(df["n_ips"])
        df = df.sort_values("n_ips")

        if type == "CDF":
            stats_df = df \
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

            fig.update_layout(title='PDF e CDF',
                            xaxis_title='Value',
                            yaxis_title='Probability',
                            showlegend=True)
            return fig
        else:
            ips_cont = df['n_ips'].value_counts()
            fig = px.bar(df, x='n_ips_str', hover_data=['org_clean', 'ip_list'])
            if org_query:
                df = df[df['org_clean'].str.contains(org_query, case=False)]
                
            fig = go.Figure()

            fig.add_trace(go.Bar(x=ips_cont.index, y=ips_cont.values, name='CVSS Rank'))

            fig.update_layout(title='Distribution of CVSS',
                    xaxis=dict(title='CVSS Rank'),
                    yaxis=dict(title='Number of registers'))

            return fig