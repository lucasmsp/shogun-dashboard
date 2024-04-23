import pandas as pd
from dash import html, dcc, dash_table
import plotly.express as px
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output


INPUT_DATA = 'v3'



# precisamos add a lógica de filtrar os elementos e outras interatividades: https://dash.plotly.com/datatable/interactivity
# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: apenas ao clicar ? por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer ?

#constructs the layout for View 3
def register_layout_query(dfs):

    # visualização 3
    q3 = [
        dbc.Row(
            children=[
                html.H1(children="View 3 - More details by CVE", className='wrapper'),
                # contém uma tabela iterativa Dash
                dbc.Row(
                    # Renders an interactive table component
                    dash_table.DataTable(

                        id='query-3-table',
                        columns=[
                            {"name": i, "id": i, "selectable": True, "deletable": True} for i in
                            sorted(dfs[INPUT_DATA].columns)
                        ],
                        # permite que a tabela seja editável
                        editable=True,
                        # permite filtragem da tabela
                        filter_action="native",
                        hidden_columns=['org_list'],
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        row_selectable='multi',
                        row_deletable=True,
                        page_current=0,
                        page_size=5,
                        style_data={
                            'whiteSpace': 'normal',
                            'height': 'auto',
                            'max-height': '15px', 'min-height': '15px', 'height': '15px'
                        }
                    ),
                    style={'margin-top': '32px'}

                ),
                html.Br(),
                dbc.Row(
                    children=[
                        dbc.Col(
                            children=[
                                html.H4("Choose input for x-axis"),
                                dcc.Dropdown(
                                    id="dropdown1",
                                    options=[
                                        {"label": "CVSS", "value": "cvss"},
                                        {"label": "Number of IPs", "value": "n_ips"},
                                        {"label": "EPSS Rank", "value": "epss_rank"},
                                        {"label": "CVSS version", "value": "cvss_version"},
                                        {"label": "CVSS Rank", "value": "epss_rank"},
                                        {"label": "Number of orgs", "value": "n_orgs"},
                                        {"label": "CVE ID", "value": "cve_id"}
                                    ],
                                    value="cvss",
                                    clearable=True,
                                ),
                            ],
                        ),
                        dbc.Col(
                            children=[
                                html.H4("Choose input for y-axis"),
                                dcc.Dropdown(
                                    id="dropdown2",
                                    options=[
                                        {"label": "CVSS", "value": "cvss"},
                                        {"label": "Number of IPs", "value": "n_ips"},
                                        {"label": "EPSS Rank", "value": "epss_rank"},
                                        {"label": "CVSS version", "value": "cvss_version"},
                                        {"label": "CVSS Rank", "value": "epss_rank"},
                                        {"label": "Number of orgs", "value": "n_orgs"},
                                        {"label": "CVE ID", "value": "cve_id"}
                                    ],
                                    value="n_ips",
                                    clearable=True,
                                ),
                            ],
                        ),
                    ],
                    style={'margin-top': '20px'}
                ),
                # dcc.Graph(
                #     id="query-3-graph",
                #     config={
                #         'displayModeBar': False,
                #         'scrollZoom': True
                #     }
                # ),
                dcc.Graph(id="graph"),
            ]
        )
    ]

    return q3

# register all the callbacks in one place
def register_callback_query(app, dfs):
    @app.callback(
        Output('query-3-table', "data"),
        Input('query-3-table', "sort_by"),
        Input('query-3-table', 'filter_query')
    )
    def update_table3(sort_by, filter_query):
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

        if filter_query:
            df = dfs[INPUT_DATA].query(filter_query)

        return df.to_dict('records')

    @app.callback(
        Output('graph', 'figure'),
        [Input('dropdown1', 'value'),
         Input('dropdown2', 'value'),
         Input('query-3-table', 'data')]
    )

    def update_bar_chart(x_axis, y_axis, data):
        df = pd.DataFrame(data)
        # define paleta de cores
        colors = px.colors.qualitative.Set1
        fig = px.scatter(df, x=x_axis, y=y_axis, title=f"{y_axis.capitalize()} vs {x_axis.capitalize()}")
        return fig
