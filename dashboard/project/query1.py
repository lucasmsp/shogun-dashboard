from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input

import pandas as pd
import plotly.express as px
import dash_ag_grid as dag

import project.base as base

INPUT_DATA = '1'
TAB_VIEW = "tab-0"

def register_layout_query(dm):
    # visualização 1
    q1 = [
        html.H1(children="View 1 - EPSS summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
                dbc.Row(
                    
                        
                    dag.AgGrid(
                        id='query-1-table',
                        columnDefs=[
                            {"headerName": 'EPSS rank', "field": "epss_rank"}, 
                            {"headerName": '# CVEs', "field": 'n_cves'},
                            {"headerName": '# IPs', "field": 'n_ips'},
                            {"headerName": '# organizations', "field": 'n_orgs'}
                        ],
                        defaultColDef={"flex": 1},
                        columnSize="responsiveSizeToFit",
                        columnSizeOptions= {"skipHeader": False},
                        style={"height": 260}
                    ),
                ),
                dbc.Row(
                    [
                        html.H4(children="Choose a type of graph: ", className='wrapper', style={'textAlign': 'Left'}),
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
                            clearable=False,
                        ),
                        dcc.Graph(
                            id="query-1-graph",
                            config={
                                'displayModeBar': False,
                                'scrollZoom': False
                            }, 
                        ),
                    ]
                )
            ]
        )
    ]
    
    return q1



def register_callback_query(dm, app):
    @app.callback(
        Output('query-1-table', "rowData"),
        Input('date-picker-single', 'value'),
        Input("general-tabs", "active_tab")
    )
    def update_table1(date_value, active_tab):
        if TAB_VIEW == active_tab:
            print(f"[INFO][query1] update_table1: {date_value} and '{active_tab}'")
            df = dm.get_view_dataset(date_value, INPUT_DATA)
            return df.to_dict('records')
        return []
            
    
    @app.callback(
        Output("query-1-graph", "figure"), 
        Input('date-picker-single', 'value'),
        Input("query-1-dropdown", "value"),
        Input("general-tabs", "active_tab")
    )
    def update_chart1(date_value, metric, active_tab):
        fig = {}
        if TAB_VIEW != active_tab:
            return fig
        print(f"[INFO][query1] update_chart1: {date_value} and '{active_tab}'")

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return fig
        
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
                labels={
                        "epss_rank": "EPSS Rank",
                        y_column: y_label
                    }
                )
        elif graph_type == "pdf plot":
            df['pdf'] = df['n_cves'] / sum(df['n_cves'])
            df = df.reset_index()
            fig = px.line(df,
                x="epss_rank", 
                y='pdf',
                )

        else:
            df['pdf'] = df['n_cves'] / sum(df['n_cves'])
            df['cdf'] = df['pdf'].cumsum()
            df = df.reset_index()
            fig = px.line(df,
                x="epss_rank", 
                y='cdf',
                )

        return fig
