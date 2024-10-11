from dash import html, dcc, callback_context
import dash_bootstrap_components as dbc

import project.query1 as query1
import project.query2_orgs as query2_orgs
import project.query2_ips as query2_ips
import project.query3 as query3
import project.query4 as query4
import project.query5 as query5

tab1_content = dbc.Card(
    dbc.CardBody(
        html.Div(children=[dbc.Row(children=query1.register_layout_query())], className="wrapper")),
    className="mt-3",
    id="tab1_content"
)

tab2_content_orgs = dbc.Card(
    dbc.CardBody(
        html.Div(children=[dbc.Row(children=query2_orgs.register_layout_query())], className="wrapper"),
    ),
    className="mt-3",
    id="tab2_content_orgs"
)

tab2_content_ips = dbc.Card(
    dbc.CardBody(
        html.Div(children=[dbc.Row(children=query2_ips.register_layout_query())], className="wrapper"),
    ),
    className="mt-3",
    id="tab2_content_ips"
)

tab3_content = dbc.Card(
    dbc.CardBody(
        html.Div(children=[dbc.Row(children=query3.register_layout_query())], className="wrapper"),
    ),
    className="mt-3",
    id="tab3_content"
)

tab4_content = dbc.Card(
    dbc.CardBody(
        html.Div(children=[dbc.Row(children=query4.register_layout_query())], className="wrapper"),
    ),
    className="mt-3",
    id="tab4_content"
)

tab5_content = dbc.Card(
    dbc.CardBody(
        html.Div(children=[dbc.Row(children=query5.register_layout_query())], className="wrapper_table",
                 style={"width": "100%", "height": "100%"}),
    ),
    className="mt-3",
    id="tab5_content"
)

def register_layout(dm):

    sidebar_header = dbc.Row(
        [
            dbc.Col(html.H3("SH🎯GUN")),
            dbc.Col(
                [
                    html.Button(
                        html.Span(className="navbar-toggler-icon"),
                        className="navbar-toggler",
                        style={
                            "color": "rgba(0,0,0,.5)",
                            "border-color": "rgba(0,0,0,.1)",
                        },
                        id="navbar-toggle",
                    ),
                    html.Button(
                        html.Span(className="navbar-toggler-icon"),
                        className="navbar-toggler",
                        style={
                            "color": "rgba(0,0,0,.5)",
                            "border-color": "rgba(0,0,0,.1)",
                        },
                        id="sidebar-toggle",
                    ),
                ],
                width="auto",
                align="center",
            ),
        ]
    )

    sidebar = html.Div(
        [
            sidebar_header,
            html.Div([html.Hr()], id="blurb"),
            # use the Collapse component to animate hiding / revealing links
            dbc.Collapse(
                dbc.Nav(
                    [
                        dbc.NavLink(
                            "Summary",
                            href="/dashboard/view1",
                            active="exact",
                        ),
                        dbc.NavLink(
                            ["Aggregated vulnerabilities", html.I(className="fas fa-chevron-right me-3", id="arrow-v2", style={"padding-left": "40px"})],
                            id="submenu-v2",
                            style={"cursor": "pointer"},
                        ),
                        dbc.Collapse(
                            dbc.Nav(
                                children=[
                                    dbc.NavLink(
                                        "by Organization",
                                        href="/dashboard/view2a",
                                        active="exact",
                                        style={"margin-top": "0px", "padding-top": "0px"}

                                    ),
                                    dbc.NavLink(
                                        "by IP",
                                        href="/dashboard/view2b",
                                        active="exact",
                                        style={"margin-top": "0px", "padding-top": "0px"}
                                    )
                                ],
                                vertical=True,
                                pills=True,
                                style={"margin-top": "0px"}
                            ),
                            id="submenu-v2-collapse",
                            style={"padding-left": "15px", "padding-top": "0px"}
                        ),
                        dbc.NavLink(
                            "Report of Common Vulnerabilities and Exposures (CVE)",
                            href="/dashboard/view3",
                            active="exact",
                        ),
                        dbc.NavLink(
                            "Representation of data through maps",
                            href="/dashboard/view4",
                            active="exact",
                        ),
                        dbc.NavLink(
                            "General analysis per record",
                            href="/dashboard/report",
                            active="exact",
                        ),
                    ],
                    vertical=True,
                    pills=True,
                ),
                id="collapse",
            ),
        ],
        id="sidebar",
        style={
            'top': '100px',
        }
    )


    nav_opts = [
        dbc.DropdownMenuItem("Profile", id="profile-menu-item"),
        dbc.DropdownMenuItem("Administrator", id="admin-menu-item", style={'display': 'none'}),
        dbc.DropdownMenuItem("Logout", id="logout-menu-item"),
    ]

    header = dbc.Navbar(
        dbc.Container(
            [
                dbc.Row(
                    [
                        html.H1(children=["SH🎯GUN - SAM/CRIVO Cybersecurity Dashboards"])
                    ],
                    className="g-3",
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
                    label="Loading...",
                    align_end=True,
                    id="username-menu"
                ),
                dcc.Interval(id='last_dump_check', interval=5 * 60 * 1000, n_intervals=0),
            ],
        ),
        color="dark",
        dark=True,
        style={"flex": "1", "color": "white", "padding-left": "120px"},
    )

    footer = html.Footer([
                html.H3(children=[
                    html.Br(),
                    html.Img(src="/assets/rnp.png", style={'height': '30px', 'verticalAlign': 'middle', 'paddingRight': '10px'}),
                    "DCC/UFMG - CERT.br - RNP"
                ],
                style={'textAlign': 'center', 'marginTop': '10px'}),
                html.Div(
                    html.H5(
                        id='last_dump_message',
                        children="Last dump: ??. Checking for new data at ??."
                    ),
                    style={'float': 'right', 'textAlign': 'right'}
                ),
            ],
            style={
                'border': '1px solid #ccc',  # Add a border at the top
                'textAlign': 'center',  # Center-align the text
                'padding': '30px',  # Add some padding for spacing
                'background-color': '#f2f2f2'  # Set a background color
            }
    )


    layout = html.Div([
            dcc.Location(id='url-redirect', refresh=False),
            sidebar,
            header,
            html.Div(id="page-content", children=tab1_content, style={'min-height': '1300px'}),
            footer,
            dcc.Store(id='store-date')
        ])

    return layout


