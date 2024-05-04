from dash import html, dcc, dash_table, callback_context
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input, State

import pandas as pd
import plotly.express as px
import re

import project.base as base


INPUT_DATA_V2a = '2a'
INPUT_DATA_V2b = '2b'


# garantir ordem das colunas mais lógica (org_clean, ip, cve_id, epss....)
# precisamos add a lógica de filtrar os elementos e outras interatividades: https://dash.plotly.com/datatable/interactivity
# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer (se for mais de um grafico, fazer como dividir os graficos na mesma linha)?
# colocar título nos graficos
# arrumar nomes das colunas nas tabelas

# def display_dropdown(cell_value):
#     dropdown_options = [{'label': value, 'value': value} for value in cell_value.split(',')]
#     return dcc.Dropdown(options=dropdown_options, value=cell_value)

def cell_callback(row):
    return html.Div([
        html.Button(f'Mostrar lista {row}', id=f'button_{row}'),
        dbc.Modal(
            id=f'modal_{row}',
            children=[
                html.Div(id=f'modal_content_{row}')
            ],
            is_open=False
        )
    ])

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
                    placeholder="Search by organization...",
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
                value=[0.8, 1.0],
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
                    placeholder="Search by CPE product...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),

            dcc.Dropdown(
                id="dropdown-cpe-version",
                options=[], # TODO: {'label': org, 'value': org} for org in sorted(dfs[INPUT_DATA_V2a]['cpe_version'].unique())],
                placeholder="CPE version",
                multi=True,
                style={
                    "width": "90%",
                    "margin": "15px",
                }
            ),

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
                    {"name": 'CVE', "id": 'cve_id'},
                    {"name": 'EPSS', "id": 'epss'},
                    {"name": 'EPSS rank', "id": 'epss_rank'},
                    {"name": 'CVSS rank', "id": 'cvss_rank'},
                    {"name": 'Product name', "id": 'cpe_product'},
                    {"name": 'Product version', "id": 'cpe_version'},
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
                }
            ),
            style={'margin-top': '32px'}
        ),
        html.Br(),
        dcc.Dropdown(
            id="dropdown-color-2a",
            options=[
                {'label': 'epss', 'value': 'epss'},
                {'label': 'cve_id', 'value': 'cve_id'},
            ],
            placeholder="Group by...",
            style={
                "width": "90%",
                "margin": "15px",
            }
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
                    {"name": 'IP list', "id": 'ip_list'},
                    {"name": 'EPSS (major)', "id": 'epss_major'},
                    {"name": 'EPSS rank (major)', "id": 'epss_rank_major'},
                    {"name": 'Product list', "id": 'cpe_list'},
                    {"name": 'CVE list', "id": 'cve_list'}
                ],
                # sort_action='custom',
                # sort_mode='multi',
                # sort_by=[],
                page_current=0,
                page_size=10,
                style_data={
                    'whiteSpace': 'normal',
                    # 'height': 'auto',
                    'max-height': '15px', 'min-height': '15px', 'height': '15px'
                },
                
            ),
            style={'margin-top': '32px'}

        ),
        html.Br(),
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
        [
            Input('date-picker-single', 'date'),
            Input("search-bar-ip", 'value'),
            Input("search-bar-org", 'value'),
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("search-bar-cpe-product", 'value'),
            Input("dropdown-cpe-version", 'value'),
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
            df = df[df['cvss_rank'].isin(cvss_query)]

        if product_query:
            df = df[df['cpe_product'].str.contains(product_query, case=False)]

        if cpe_version_query:
            df = df[df['cpe_version'].isin(cpe_version_query)]

        df = df.sort_values(by=['epss'], ascending=True)

        return df.to_dict('records')

    @app.callback(
        Output('query-2a-graph', 'figure'),
        [
            Input('date-picker-single', 'date'),
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("dropdown-cpe-version", 'value'),
            Input("dropdown-color-2a", 'value'),
        ]
    )
    def update_graph2a(date_value, epss_query, cvss_query, cpe_version_query, color):
        
        print("[INFO] query 2 - update_graph2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2a)

        if epss_query:
            epss_min, epss_max = epss_query
            df = df[(df['epss'] >= epss_min) & (df['epss'] <= epss_max)]

        if cvss_query:
            df = df[df['cvss_rank'].isin(cvss_query)]

        if cpe_version_query:
            df = df[df['cpe_version'].isin(cpe_version_query)]
        
        df = df.sort_values(by=['cvss_rank'], ascending=True)
        severity_mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }

        df['severity'] = df['cvss_rank'].map(severity_mapping)
        df = df.sort_values(by='severity', ascending=True)

        # df = df.groupby('cvss_rank').sum()
        # print(df)
        # temp = df.groupby("cvss_rank").agg(LIST_IP=("ip_str", set), N_IPS=("ip_str", "count")).reset_index()
        # temp['LIST_IP'] = temp['LIST_IP'].str.join(', ')
        fig = px.bar(df, x='cvss_rank', hover_data=["ip_str", "cve_id"], barmode='stack')
        # df = df.groupby(['cvss_rank'])
        if color:
            df = df.sort_values(by=['severity', color], ascending=True)
            if color == 'cve_id':
                # df = df.groupby("cvss_rank").agg(LIST_IP=("ip_str", set), N_IPS=("ip_str", "count")).reset_index()
                # df['LIST_IP'] = df['LIST_IP'].str.join(', ')
                fig = px.bar(df, x='cvss_rank', color=color, hover_data=["ip_str", "cve_id"], barmode='stack')
            else:
                fig = px.bar(df, x='cvss_rank', color=color, hover_data=["ip_str", "cve_id"], barmode='stack')



        return fig
    
    def contar_virgulas_str(texto):
        return str(len(re.findall(r",", texto)) + 1)
    
    def contar_virgulas(texto):
        return len(re.findall(r",", texto)) + 1
    

    @app.callback(
        Output('query-2b-table', "data"),
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

        # if len(sort_by):
        #     print(sort_by)
        #     print(df)
        #     df = df.sort_values(
        #         [col['column_id'] for col in sort_by],
        #         ascending=[
        #             col['direction'] == 'asc'
        #             for col in sort_by
        #         ],
        #         inplace=True
        #     )
        #     print(df)

        # org_clean, ip, epss_major, epss_rank_major, cpe, cve 
        
        return df.to_dict('records')
    
    @app.callback(
        Output('query-2b-graph', 'figure'),
        Input('date-picker-single', 'date'),
        Input("search-bar-org-2b", 'value')
    )
    def update_graph2b(date_value, org_query):
        print("[INFO] query 2 - update_graph2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2b)

        df["n_ips_str"] = df["ip_list"].apply(contar_virgulas_str)
        df["n_ips"] = df["ip_list"].apply(contar_virgulas)
        df = df.sort_values("n_ips")
        fig = px.bar(df, x='n_ips_str', hover_data=['org_clean', 'ip_list'])
        if org_query:
            df = df[df['org_clean'].str.contains(org_query, case=False)]
            fig = px.bar(df, x='n_ips_str', hover_data=['org_clean', 'ip_list'])



        return fig
