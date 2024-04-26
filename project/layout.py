from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc


import project.query1 as query1
import project.query2 as query2
import project.query3 as query3

import project.base as base

available_datasets = base.check_available_datasets()

def register_layout():
    layout = html.Div(
        children=[
            html.Div(
                children=[
                    html.P(children="📊", className="header-emoji"),
                    html.H1(children="TLHOP/SAM Analytics on EPSS", className="header-title")
                    
                ],
                className="header",
            ),

            html.Div(
                children=[
                    dbc.Row([
                        html.Br(),
                    ])
                ]
            ),

            html.Div(
                [
                    dbc.Container([
                        dbc.Row([
                            dbc.Col(html.Div(
                                html.H3(
                                    children=("This dashboard is intended for vulnerability analysis using EPSS as a risk score."),
                                    className="menu-title"
                                )
                            ), width={"size": 12})
                        ]),
                        dbc.Row([
                            dbc.Col(html.Div(html.H3(children="Analysis day: "), className='alignright'), width={"size": 9}),
                            dbc.Col(html.Div([
                                dcc.DatePickerSingle(
                                    id='date-picker-single',
                                    min_date_allowed=available_datasets[0],
                                    max_date_allowed=available_datasets[-1],
                                    initial_visible_month=available_datasets[0],
                                    date=available_datasets[-1]
                            )], className='aligncenter'), width={"size": 3, "order": "last"})
                        
                    ], align="center")]),
            ], className="menu"),

            html.Div(
                children=[
                    dbc.Row([
                        html.Br(),
                    ])
                ]
            ),
            html.Div(children=[dbc.Row(children=query1.register_layout_query())], className="wrapper"),
            html.Div(children=[dbc.Row(children=query2.register_layout_query())], className="wrapper"),
            html.Div(children=[dbc.Row(children=query3.register_layout_query())], className="wrapper"),
            
        ]
    )
    return layout
