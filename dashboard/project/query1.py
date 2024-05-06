from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input

import pandas as pd
import plotly.express as px

import project.base as base

INPUT_DATA = '1'

def register_layout_query(dm):
    # visualização 1
    q1 = [
        html.H1(children="View 1 - EPSS summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container([
            dbc.Row(
                children=[
                    dbc.Col(
                        dash_table.DataTable(
                            id='query-1-table',
                            columns=[
                                {"name": 'EPSS rank', "id": "epss_rank"}, 
                                {"name": '# CVEs', "id": 'n_cves'},
                                {"name": '# IPs', "id": 'n_ips'},
                                {"name": '# organizations', "id": 'n_orgs'}
                            ],
                            sort_action='custom',
                            sort_mode='multi',
                            sort_by=[],
                            style_cell={
                                'paddingRight': '10px', 
                                'paddingLeft': '10px',
                                'text-align': 'center'
                            },
                            style_data={
                                'whiteSpace': 'normal',
                                'height': 'auto',
                                'max-height': '80px',
                                'min-height': '50px', 
                                'minWidth': '80px', 
                                'width': '200px', 
                                'maxWidth': '250px',
                            },
                            fill_width=False
                        ),
                        style={
                            'marginTop': '32px', 
                            'marginRight': '10px',
                            'textAlign': 'center',
                            'fontSize': '16px',
                            'fontFamily': "Lato, sans-serif",
                            },
                        width = 4, 
                    ),
                    dbc.Col([
                            html.H4(children="Choose a type of graph: ", className='wrapper'),
                            dcc.Dropdown(
                                id="query-1-dropdown",
                                options=[
                                    "Bar plot - Number of CVEs by EPSS Rank", 
                                    "Bar plot - Number of organizations by EPSS Rank",
                                    "Bar plot - Number of IPs by EPSS Rank",
                                    "CDF plot - Number of CVEs by EPSS Rank",
                                    "PDF plot - Number of CVEs by EPSS Rank"
                                ],
                                value="Bar plot - Number of CVEs by EPSS Rank",
                                clearable=False
                            ),
                            dcc.Graph(
                                id="query-1-graph",
                                config={
                                    'displayModeBar': False,
                                    'scrollZoom': False
                                }, responsive=True
                            )
                        ], 
                        width = 4,
                    )
                ],
                justify="center")
            ]
        )
    ]

    
    return q1



def register_callback_query(dm, app):
    
    @app.callback(
        Output('query-1-table', "data"),
        Input('date-picker-single', 'date'),
        Input('query-1-table', "sort_by"),
    )
    def update_table1(date_value, sort_by):
        print("[INFO] update_table1: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)
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
        Input('date-picker-single', 'date'),
        Input("query-1-dropdown", "value")
    )
    def update_chart1(date_value, metric):
        print("[INFO] update_chart1", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        config = {'displayModeBar': False}

        y_column = "n_cves"
        y_label = "# CVEs"
        graph_type = "bar plot"

        if metric == "Bar plot - Number of CVEs by EPSS Rank":
            y_column = "n_cves"
            y_label = "# CVEs"
            graph_type = "bar plot"
        elif metric == "Bar plot - Number of organizations by EPSS Rank":
            y_column = "n_orgs"
            y_label = "# Orgs"
            graph_type = "bar plot"
        elif metric == "Bar plot - Number of IPs by EPSS Rank":
            y_column = "n_ips"
            y_label = "# IPs"
            graph_type = "bar plot"
        elif metric == "PDF plot - Number of CVEs by EPSS Rank":
            y_column = "n_cves"
            y_label = "# CVEs"
            graph_type = "pdf plot"
        elif metric == "CDF plot - Number of CVEs by EPSS Rank":
            y_column = "n_cves"
            y_label = "# CVEs"
            graph_type = "cdf plot"
        
        if graph_type == "bar plot":
            fig = px.bar(df,
                x="epss_rank", 
                y=y_column, 
                barmode="group", 
                title=metric, 
                labels={
                        "epss_rank": "EPSS Rank",
                        y_column: y_label
                    }
                )
        elif graph_type == "pdf plot":
            df['pdf'] = df['n_cves'] / sum(df['n_cves'])
            df = df.reset_index()
            fig = px.bar(df,
                x="epss_rank", 
                y='pdf', 
                barmode="group", 
                title=metric, 
                labels={
                        "epss_rank": "EPSS Rank",
                        'pdf': 'Probability Density'
                    }
                )

        else:
            df['pdf'] = df['n_cves'] / sum(df['n_cves'])
            df['cdf'] = df['pdf'].cumsum()
            df = df.reset_index()
            fig = px.bar(df,
                x="epss_rank", 
                y='cdf', 
                barmode="group", 
                title=metric, 
                labels={
                        "epss_rank": "EPSS Rank",
                        'cdf': 'Probability'
                    }
                )

        fig.update_traces(width=1)
        fig.update_layout(
            font=dict(
                family="Lato, sans-serif",
                size=16,
            ),
        )

        return fig
