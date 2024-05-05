from dash import html, dcc, dash_table, callback_context
import dash_bootstrap_components as dbc

import plotly.graph_objects as go

from dash.dependencies import Output, Input, State

import pandas as pd
import numpy as np
import plotly.express as px

import project.base as base

import re

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

# def display_tooltip(row):
#     colunas_df_limpo = ['org_clean', 'epss_major']
#     colunas_ausentes = [coluna for coluna in colunas_df_original if coluna not in colunas_df_limpo]
#     tooltip_text = ", ".join(colunas_ausentes)
#     return tooltip_text

def register_layout_query():
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
            dcc.Dropdown(
                id="dropdown-cpe-version",
                options=[], # TODO: [{'label': org, 'value': org} for org in sorted(dfa['cpe_version'].unique()) if date_pick],
                placeholder="Product version",
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
        dbc.Row(
            [
                dbc.Col(
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
                ),
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-type-2a",
                        options=[
                            {'label': 'Bars', 'value': 'Bars'},
                            {'label': 'CDF', 'value': 'CDF'},
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

        dbc.Row(
            [
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-type-2b",
                        options=[
                            {'label': 'Bars', 'value': 'Bars'},
                            {'label': 'CDF', 'value': 'CDF'},
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


def register_callback_query(app):
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
        df = base.get_dataset(date_value, INPUT_DATA_V2a)
        date_pick = date_value
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
            Input("dropdown-type-2a", 'value'),
        ]
    )
    def update_graph2a(date_value, epss_query, cvss_query, cpe_version_query, color, type):

        print("[INFO] query 2 - update_graph2a: ", date_value)
        df = base.get_dataset(date_value, INPUT_DATA_V2a)

        if epss_query:
            epss_min, epss_max = epss_query
            df = df[(df['epss'] >= epss_min) & (df['epss'] <= epss_max)]

        if cvss_query:
            df = df[df['cvss_rank'].isin(cvss_query)]

        if cpe_version_query:
            df = df[df['cpe_version'].isin(cpe_version_query)]

        
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
            # stats_df.plot(x = 'value', y = ['pdf', 'cdf'], grid = True)
            fig = go.Figure()
            # Adicionar linha para pdf
            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['pdf'], mode='lines', name='PDF'))

            # Adicionar linha para cdf
            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['cdf'], mode='lines', name='CDF'))

            # Atualizar layout do gráfico
            fig.update_layout(title='PDF e CDF',
                            xaxis_title='Valor',
                            yaxis_title='Probabilidade',
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
            severity_counts = df['severity'].value_counts().sort_index()

            # df = df.sort_values(by='severity', ascending=True)

            # df = df.groupby('cvss_rank').sum()
            # print(df)
            # temp = df.groupby("cvss_rank").agg(LIST_IP=("ip_str", set), N_IPS=("ip_str", "count")).reset_index()
            # temp['LIST_IP'] = temp['LIST_IP'].str.join(', ')

            # data = go.Bar(x=df['cvss_rank'])

            fig = go.Figure()

            fig.add_trace(go.Bar(x=cvss_counts.index, y=cvss_counts.values, name='CVSS Rank'))

            # Adicionando a contagem de registros para cada 'severity' no eixo x
            # fig.add_trace(go.Bar(x=severity_counts.index, y=severity_counts.values, name='Severity'))

            # Atualizando o layout do gráfico
            fig.update_layout(title='Distribuição de CVSS Rank',
                    xaxis=dict(title='CVSS Rank'),
                    yaxis=dict(title='Quantidade de Registros'))

            # fig = go.Figure(df, x='cvss_rank', hover_data=["ip_str", "cve_id"], barmode='stack')
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
        df = base.get_dataset(date_value, INPUT_DATA_V2b)

        if org_query:
            df = df[df['org_clean'].str.contains(org_query, case=False)]
        if ip_query:
            df = df[df['ip_list'].str.contains(ip_query, case=False)]
        if cpe_query:
            df = df[df['cpe_list'].str.contains(cpe_query, case=False)]
        if cve_query:
            df = df[df['cve_list'].str.contains(cve_query, case=False)]

        print(df.columns)

        df_limpo = df[['org_clean', 'epss_major']]
        print(df.columns)

        def display_tooltip(row):
            colunas_df_limpo = ['org_clean', 'epss_major']
            colunas_ausentes = [coluna for coluna in df.columns if coluna not in colunas_df_limpo]
            tooltip_text = ", ".join(colunas_ausentes)
            return tooltip_text


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

        return df_limpo.to_dict('records')

    @app.callback(
        Output('query-2b-graph', 'figure'),
        Input('date-picker-single', 'date'),
        Input("search-bar-org-2b", 'value'),
        Input("dropdown-type-2b", 'value'),
    )
    def update_graph2b(date_value, org_query, type):
        print("[INFO] query 2 - update_graph2b: ", date_value)
        df = base.get_dataset(date_value, INPUT_DATA_V2b)
        df["n_ips_str"] = df["ip_list"].apply(contar_virgulas_str)
        df["n_ips"] = df["ip_list"].apply(contar_virgulas)
        df = df.sort_values("n_ips")

        if type == "CDF":
            stats_df = df \
                .groupby('n_ips_str') \
                ['n_ips_str'] \
                .agg('count') \
                .pipe(pd.DataFrame) \
                .rename(columns = {'n_ips_str': 'frequency'})

            # PDF
            stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])

            # CDF
            stats_df['cdf'] = stats_df['pdf'].cumsum()
            stats_df = stats_df.reset_index()
            # stats_df.plot(x = 'value', y = ['pdf', 'cdf'], grid = True)
            fig = go.Figure()
            # Adicionar linha para pdf
            fig.add_trace(go.Scatter(x=stats_df['n_ips_str'], y=stats_df['pdf'], mode='lines', name='PDF'))

            # Adicionar linha para cdf
            fig.add_trace(go.Scatter(x=stats_df['n_ips_str'], y=stats_df['cdf'], mode='lines', name='CDF'))

            # Atualizar layout do gráfico
            fig.update_layout(title='PDF e CDF',
                            xaxis_title='Valor',
                            yaxis_title='Probabilidade',
                            showlegend=True)
            return fig
        else:
            ips_cont = df['n_ips'].value_counts()
            fig = px.bar(df, x='n_ips_str', hover_data=['org_clean', 'ip_list'])
            if org_query:
                df = df[df['org_clean'].str.contains(org_query, case=False)]
                
            fig = go.Figure()

            fig.add_trace(go.Bar(x=ips_cont.index, y=ips_cont.values, name='CVSS Rank'))

            # Adicionando a contagem de registros para cada 'severity' no eixo x
            # fig.add_trace(go.Bar(x=severity_counts.index, y=severity_counts.values, name='Severity'))

            # Atualizando o layout do gráfico
            fig.update_layout(title='Distribuição de CVSS Rank',
                    xaxis=dict(title='CVSS Rank'),
                    yaxis=dict(title='Quantidade de Registros'))

            # fig = go.Figure(df, x='cvss_rank', hover_data=["ip_str", "cve_id"], barmode='stack')
            # df = df.groupby(['cvss_rank'])
            # if color:
            #     df = df.sort_values(by=['severity', color], ascending=True)
            #     if color == 'cve_id':
            #         # df = df.groupby("cvss_rank").agg(LIST_IP=("ip_str", set), N_IPS=("ip_str", "count")).reset_index()
            #         # df['LIST_IP'] = df['LIST_IP'].str.join(', ')
            #         fig = px.bar(df, x='cvss_rank', color=color, hover_data=["ip_str", "cve_id"], barmode='stack')
            #     else:
            #         fig = px.bar(df, x='cvss_rank', color=color, hover_data=["ip_str", "cve_id"], barmode='stack')



            return fig
        
    
    def display_tooltip(row):
        colunas_df_limpo = ['org_clean', 'epss_major']
        colunas_ausentes = [coluna for coluna in colunas_df_original if coluna not in colunas_df_limpo]
        tooltip_text = ", ".join(colunas_ausentes)
        return tooltip_text


