from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc

from dash.dependencies import Output, Input
import pandas as pd
import plotly.express as px

INPUT_DATA = 'v3'

# precisamos add a lógica de filtrar os elementos e outras interatividades: https://dash.plotly.com/datatable/interactivity
# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: apenas ao clicar ? por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer ?


def register_layout_query(dfs):
    # visualização 3
    q3 = [
        dbc.Row(
            children=[
                html.H1(children="View 3 - More details by CVE", className='wrapper'),
                dbc.Row(
                    dash_table.DataTable(

                        id='query-3-table',
                        columns=[
                            {"name": i, "id": i} for i in sorted(dfs[INPUT_DATA].columns)
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
                    id="guery-3-graph",
                    config={
                        'displayModeBar': False,
                        'scrollZoom': True
                    }
                )
            ]
        )
    ]

    
    return q3


def register_callback_query(app, dfs):
    
    @app.callback(
        Output('query-3-table', "data"),
        Input('query-3-table', "sort_by"),
    )
    def update_table3(sort_by):

        df = dfs[INPUT_DATA]
        df['org_list'] = df['org_list'].str.join(', ')
        
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
    