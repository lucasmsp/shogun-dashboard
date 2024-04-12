from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc

import project.query1 as query1
import project.query2 as query2
import project.query3 as query3

def register_layout(dfs):
    layout = html.Div(
        children=[
            html.Div(
                children=[
                    html.P(children="📊", className="header-emoji"),
                    html.H1(
                        children="TLHOP/SAM Analytics on EPSS", className="header-title"
                    ),
                    html.P(
                        children=(
                            "This dashboard is intended for vulnerability analysis using EPSS as a risk score."
                        ),
                        className="header-description",
                    ),
                ],
                className="header",
            ),
            
            # margem
            html.Div(
                children=[
                    dbc.Row([
                        html.Br(),
                    ])
                ]
            ),
            
            html.Div(children=[dbc.Row(children=query1.register_layout_query(dfs))], className="wrapper"),
            html.Div(children=[dbc.Row(children=query2.register_layout_query(dfs))], className="wrapper"),
            html.Div(children=[dbc.Row(children=query3.register_layout_query(dfs))], className="wrapper"),

            
            
            
        ]
    )
    return layout