from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc

import project.query1 as query1
import project.query2 as query2
import project.query3 as query3
import project.query4 as query4

import project.base as base


def register_layout(dm, username):

    tab1_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query1.register_layout_query(dm))], className="wrapper")),
        className="mt-3",
    )

    tab2_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query2.register_layout_query(dm))], className="wrapper"),
        ),
        className="mt-3",
    )

    tab3_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query3.register_layout_query(dm))], className="wrapper"),
        ),
        className="mt-3",
    )

    tab4_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query4.register_layout_query(dm))], className="wrapper"),
        ),
        className="mt-3",
    )

    # Iframe to embed the HTML page
    iframe_content = dbc.Card(
        dbc.CardBody(
            html.Div(
                children=[
                    html.Iframe(
                        src="/details_ip",
                        style={"width": "100%", "height": "2000px"}
                    )
                ],
                className="wrapper_table"
            ),
        ),
        className="mt-3",
    )

    layout = html.Div(
        children=[
            html.Div(
                children=[
                    html.P(children="📊", className="header-emoji"),
                    html.Div(
                        children=[
                            html.H1(children="TLHOP/SAM Cybersecurity Dashboards", className="header-title"),
                            html.H3(f"Logged in as: {username}", className="header-logged-as")
                        ],
                        style={"flex": "1"}
                    ),
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
            html.Br(),
            html.Div(
                [
                    dbc.Container(
                        [
                            dbc.Row([
                                dbc.Col(html.Div(
                                    html.H3(
                                        children=(
                                            "This dashboard is intended for vulnerability analysis using EPSS as a risk score."
                                        ),
                                        className="menu-title"
                                    )
                                ), width={"size": 12})
                            ]),
                            dbc.Row(
                                [
                                    dbc.Col(
                                        html.Div(
                                            dcc.Dropdown(
                                                options=[], 
                                                value=None, 
                                                id='date-picker-single', 
                                                placeholder="Analysis day",
                                                clearable=False,
                                                multi=False,
                                                style={'minWidth': '100%'}
                                            ),
                                            className='alignright',
                                            style={'width': '100%', 'display': 'inline-block'}
                                        ),
                                        width=5
                                    ),
                                    dbc.Col(
                                        html.Div(
                                            html.H5(
                                                id='last_dump_message',
                                                children="Last dump: ??. Checking for new data at ??."
                                            ),
                                            className='alignleft'
                                        ),
                                        width=5
                                    )
                                ],
                                align="center",
                            ),
                            dcc.Interval(id='last_dump_check', interval=15 * 1000, n_intervals=0),
                        ]
                    ),
                ],
                className="menu",
                style={
                    "padding": "15px 15px 150px 15px"
                }
            ),

            html.Div(
                children=[
                    dbc.Row([
                        html.Br(),
                    ])
                ]
            ),

            html.Br(),

            dbc.Tabs(
                [
                    dbc.Tab(tab1_content, label="View 1 - EPSS summary"),
                    dbc.Tab(tab2_content, label="View 2 - by organizations/IP"),
                    dbc.Tab(tab3_content, label="View 3 - More details by CVE"),
                    dbc.Tab(tab4_content, label="View 4 - Maps"),
                    dbc.Tab(iframe_content, label="Advanced Analysis (IP Data)"), 
                ],
                style={
                    "paddingLeft": "20px"
                },
                id="general-tabs",
                active_tab='tab-0'
            )
        ]
    )
    return layout
