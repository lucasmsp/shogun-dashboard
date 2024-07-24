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

    nav_opts = [
        dbc.DropdownMenuItem(username, header=True),
        dbc.DropdownMenuItem("Profile", id="profile-menu-item"),
        dbc.DropdownMenuItem("Administrator", id="admin-menu-item", style={'display': 'none'}),
        dbc.DropdownMenuItem("Logout", id="logout-menu-item"),
    ]

    if username == "admin":
        nav_opts[2].style = {'display': 'block'}

    navbar = dbc.Navbar(
                dbc.Container(
                    [
                        dbc.Row([
                            html.H1(children=["📊 TLHOP/SAM Cybersecurity Dashboards"])
                            ], className="g-0",
                        ),
                        dbc.NavItem(
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
                                )
                            ), class_name="ms-4", style={'width': '10vh', 'display': 'inline-block', "color": "black"}
                        ),
                        dbc.DropdownMenu(
                            children=nav_opts,
                            nav=True,
                            in_navbar=True,
                            label=username,
                            align_end=True
                        ),
                        dcc.Interval(id='last_dump_check', interval=15 * 1000, n_intervals=0),
                ]),
                color="dark",
                dark=True,
                style={"flex": "1", "color": "white"}
            )

    layout = html.Div(
        children=[
            dcc.Location(id='url-redirect', refresh=True),
            navbar,
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
            ),

            html.Footer([
                html.Div(
                    html.H5(
                            id='last_dump_message',
                            children="Last dump: ??. Checking for new data at ??."
                        ),
                        style={'float': 'left', 'textAlign': 'left'}
                ),
                html.H3(children=(
                    html.A(
                        html.I(className="fab fa-github"), # Icon from font awesome
                        href="https://github.com/lucasmsp/tlhop-epss-app" ,
                        target="_blank"
                    ), 
                    " Thread-Limiting Holistic Open Platform (TLHOP) Project - DCC/UFMG - CERT.br  | 2024"))
                ],
                style={
                        'border': '1px solid #ccc',     # Add a border at the top
                        'textAlign': 'center',         # Center-align the text
                        'padding': '30px',              # Add some padding for spacing
                        'background-color': '#f2f2f2'   # Set a background color
                }
            )
        ]
    )
    return layout
