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

def register_layout_query(dfs):
    # visualização 2a
    q2 = [
        html.H1(children="View 2 - by organizations/IP", className='wrapper'),
        html.Br(),
        
        html.H2(children="Highest EPSS for each org/IP", className='wrapper'),
        dbc.Row(
            dash_table.DataTable(

                id='query-2a-table',
                columns=[
                    {"name": i, "id": i} for i in sorted(dfs[INPUT_DATA_V2a].columns)
                ],
                sort_action='custom',
                sort_mode='multi',
                sort_by=[],
                page_current=0,
                page_size=10,
                style_data={
                    'whiteSpace': 'normal',
                    'height': 'auto',
                    'max-height': '15px', 'min-height': '15px', 'height': '15px'
                }
            ),
            style={'margin-top': '32px'}
        ),
        html.Br(),

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
                    'height': 'auto',
                    'max-height': '15px', 'min-height': '15px', 'height': '15px'
                }
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
        Input('query-2a-table', "sort_by")
    )
    def update_table2a(sort_by):

        df = dfs[INPUT_DATA_V2a]
        if len(sort_by):
            df = df.sort_values(
                [col['column_id'] for col in sort_by],
                ascending=[
                    col['direction'] == 'asc'
                    for col in sort_by
                ],
                inplace=False
            )

        return df.to_dict('records')
    
    
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
                inplace=False
            )

        return df.to_dict('records')