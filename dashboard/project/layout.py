from dash import html, dcc
import dash_bootstrap_components as dbc

import project.query1 as query1
import project.query2 as query2
import project.query3 as query3
import project.query4 as query4
import project.query5 as query5

def register_layout(dm):

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

    tab5_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=query5.register_layout_query(dm))], className="wrapper_table",  style={"width": "100%", "height": "100%"}),
        ),
        className="mt-3",
    )
    

    nav_opts = [
        dbc.DropdownMenuItem("Profile", id="profile-menu-item"),
        dbc.DropdownMenuItem("Administrator", id="admin-menu-item", style={'display': 'none'}),
        dbc.DropdownMenuItem("Logout", id="logout-menu-item"),
    ]

    navbar = dbc.Navbar(
                dbc.Container(
                    [
                        dbc.Row([
                            html.H1(children=["📊 SAM/CRIVO Cybersecurity Dashboards"])
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
                                        style={'minWidth': '200px'}
                                    ),                                    
                                )
                            ), class_name="ms-4", style={'width': '10vh', 'display': 'inline-block', "color": "black"}
                        ),
                        dbc.DropdownMenu(
                            children=nav_opts,
                            nav=True,
                            in_navbar=True,
                            label="Loading...",
                            align_end=True,
                            id="username-menu"
                        ),
                        dcc.Interval(id='last_dump_check', interval=5 * 60 * 1000, n_intervals=0),
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
                    dbc.Tab(tab5_content, label="Advanced Analysis (IP Data)"), 
                ],
                style={
                    "paddingLeft": "20px"
                },
                id="general-tabs",
                active_tab='tab-0'
            ),

            html.Footer([
                html.H3(children=[
                    html.Br(),
                    html.Img(src="/assets/rnp.png", style={'height': '30px', 'verticalAlign': 'middle', 'paddingRight': '10px'}),
                    "DCC/UFMG - CERT.br - RNP"
                ],
                style={'textAlign': 'center', 'marginTop': '20px'}),
                html.Div(
                    html.H5(
                        id='last_dump_message',
                        children="Last dump: ??. Checking for new data at ??."
                    ),
                    style={'float': 'left', 'textAlign': 'left'}
                ),
            ],
            style={
                'border': '1px solid #ccc',  # Add a border at the top
                'textAlign': 'center',  # Center-align the text
                'padding': '30px',  # Add some padding for spacing
                'background-color': '#f2f2f2'  # Set a background color
            }),

            dcc.Store(id='store-date')
        ]
    )
    return layout
