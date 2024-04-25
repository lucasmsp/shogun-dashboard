from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc

from dash.dependencies import Output, Input
import pandas as pd
import plotly.express as px

INPUT_DATA = 'v1'

def register_layout_query(dfs):
    # visualização 1
    q1 = [
        dbc.Row(
            children=[
                html.H1(children="View 1 - EPSS summary", className='wrapper'),
                dbc.Row(
                    dash_table.DataTable(

                        id='query-1-table',
                        columns=[
                            {"name": i, "id": i} for i in sorted(dfs[INPUT_DATA].columns)
                        ],
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        style_data={
                            'whiteSpace': 'normal',
                            'height': 'auto',
                            'max-height': '15px', 'min-height': '15px', 'height': '15px'
                        }
                    ),
                    style={'margin-top': '32px'}

                ),
                html.Br(),
                html.H4(children="Number of Vulnerabilities in each EPSS rank by metric", className='wrapper'),
                dcc.Dropdown(
                    id="query-1-dropdown",
                    options=["n_cves","n_orgs","n_ips"],
                    value="n_cves",
                    clearable=False
                ),
                dcc.Graph(
                    id="query-1-graph",
                    config={
                        'displayModeBar': False,
                        'scrollZoom': True
                    }
                )
            ]
        )
    ]

    
    return q1



def register_callback_query(app, dfs):
    
    @app.callback(
        Output('query-1-table', "data"),
        Input('query-1-table', "sort_by"),
    )
    def update_table1(sort_by):

        df = dfs[INPUT_DATA]
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
        Output("query-1-graph", "figure"), 
        Input("query-1-dropdown", "value")
    )
    def update_bar_chart(metric):
        df = dfs[INPUT_DATA]
        config = {'displayModeBar': False}
        fig = px.bar(df, x="epss_rank", y=metric, barmode="group")
        return fig