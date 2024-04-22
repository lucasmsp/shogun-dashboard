from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc

from dash.dependencies import Output, Input
import pandas as pd
import plotly.express as px


INPUT_DATA_V2a = 'v2a'
INPUT_DATA_V2b = 'v2b'


# garantir ordem das colunas mais lógica (org_clean, ip, cve_id, epss....)
# precisamos add a lógica de filtrar os elementos e outras interatividades: https://dash.plotly.com/datatable/interactivity
# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer (se for mais de um grafico, fazer como dividir os graficos na mesma linha)?

def display_dropdown(cell_value):
    dropdown_options = [{'label': value, 'value': value} for value in cell_value.split(',')]
    return dcc.Dropdown(options=dropdown_options, value=cell_value)

def register_layout_query(dfs):
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
                    placeholder="Search by CPE product...",
                    style={
                        "width": "90%",
                        "margin": "15px"
                    }
                )
            ]),

            dcc.Dropdown(
                id="dropdown-cpe-version",
                options=[{'label': org, 'value': org} for org in sorted(dfs[INPUT_DATA_V2a]['cpe_version'].unique())],
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
                options=[{'label': org, 'value': org} for org in sorted(dfs[INPUT_DATA_V2a]['cvss_rank'].unique())],
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


    columns_order = [
        "org_clean",
        "ip_str",
        "cve_id",
        "epss",
        "cpe_version",
        "cpe_product",
        "cvss_rank",
        "epss_rank",
    ]

    q2 = [
        html.H1(children="View 2 - by organizations/IP", className='wrapper'),
        html.Br(),
        html.H2(children="Highest EPSS for each org/IP", className='wrapper'),
        filters_2a,
        dbc.Row(
            dash_table.DataTable(
                id='query-2a-table',
                columns=[
                    {"name": col, "id": col} for col in columns_order
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
        dbc.Row(
            dash_table.DataTable(

                id='query-2b-table',
                columns=[
                    {"name": i, "id": i} for i in sorted(dfs[INPUT_DATA_V2b].columns)
                ],
                sort_action='custom',
                sort_mode='multi',
                sort_by=[],
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


def register_callback_query(app, dfs):
    @app.callback(
        Output('query-2a-table', "data"),
        [
            Input("search-bar-ip", 'value'),
            Input("search-bar-org", 'value'),
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("search-bar-cpe-product", 'value'),
            Input("dropdown-cpe-version", 'value'),
        ]
    )
    def update_table2a(ip_query, org_query, epss_query, cvss_query, product_query, cpe_version_query):

        df = dfs[INPUT_DATA_V2a]
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
            Input("epss-range-slider", 'value'),
            Input("cvss-rank-checklist", 'value'),
            Input("dropdown-cpe-version", 'value'),
            Input("dropdown-color-2a", 'value'),
        ]
    )
    def update_graph2a(epss_query, cvss_query, cpe_version_query, color):
        
        df = dfs[INPUT_DATA_V2a]
        if epss_query:
            epss_min, epss_max = epss_query
            df = df[(df['epss'] >= epss_min) & (df['epss'] <= epss_max)]

        if cvss_query:
            df = df[df['cvss_rank'].isin(cvss_query)]

        if cpe_version_query:
            df = df[df['cpe_version'].isin(cpe_version_query)]

        df = df.sort_values(by=['cvss_rank'], ascending=True)
        fig = px.bar(df, x='cvss_rank', hover_data="ip_str")

        if color:
            df = df.sort_values(by=['cvss_rank', color], ascending=True)
            fig = px.bar(df, x='cvss_rank', color=color, hover_data="ip_str")



        return fig
    

    @app.callback(
        Output('query-2b-table', "data"),
        Input('query-2b-table', "sort_by")
    )
    def update_table2b(sort_by):

        df = dfs[INPUT_DATA_V2b]
        df['cpe_list'] = df['cpe_list'].str.join(', ')
        df['ip_list'] = df['ip_list'].str.join(', ')
        df['cve_list'] = df['cve_list'].str.join(', ')

        if len(sort_by):
            df = df.sort_values(
                [col['column_id'] for col in sort_by],
                ascending=[
                    col['direction'] == 'asc'
                    for col in sort_by
                ],
                inplace=True
            )

        return df.to_dict('records')
