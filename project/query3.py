import json

import project.base as base
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd

INPUT_DATA = '3'
def dash_components():

    components_1 = html.Div([
        html.Div(children=[
            html.Center([
                dcc.Input(
                    id="search-bar-cve",
                    type="search",
                    placeholder="Search by CVE...",
                    style={
                        "width": "100%",
                        "margin": "15px"
                    }
                )
            ]),

            dcc.Dropdown(
                placeholder="CVSS version",
                id='dropdown-cvss-version',
                options=[
                    {'label': '3.1', 'value': '3.1'},
                    {'label': '3.0', 'value': '3.0'},
                    {'label': '2.1', 'value': '2.1'},
                ],
                multi=False,
                style={
                    "width": "100%",
                    "margin": "7px",
                },
            ),

            html.Label(
                children='Choose the CVSS range',
                style={
                    "margin-left": "30px",
                    "margin-bottom": "10px",
                }
            ),
            dcc.RangeSlider(
                id='cvss-range-slider',
                min=0,
                max=10,
                count=1,
                value=[5, 6],
                tooltip={
                    'placement': 'top',
                    'always_visible': True,
                },
                allowCross=False,
            ),

            html.Label(
                children='Choose the EPSS range',
                style={
                    "margin-left": "30px",
                    "margin-bottom": "10px",
                }
            ),
            dcc.RangeSlider(
                id='epss-range-slider',
                min=0,
                max=1,
                step=0.1,
                value=[0.5, 0.7],
                tooltip={
                    'placement': 'top',
                    'always_visible': True,
                },
                allowCross=False,
            ),
        ], style={'padding': 10, 'flex': 1}),

        html.Div(children=[
            html.Center([
                dcc.Input(
                    id='search-bar-org',
                    type="search",
                    placeholder="Org filter expression ('>', '<', '=','>=', '<=') e.g., '> 30'",
                    style={
                        "width": "100%",
                        "margin": "15px"
                    }
                )
            ]),
            html.Center([
                dcc.Input(
                    id='search-bar-ip',
                    type="search",
                    placeholder="IP filter expression ('>', '<', '=','>=', '<=') e.g., '> 30'",
                    style={
                        "width": "100%",
                        "margin": "15px"
                    }
                )
            ]),

        ],
            style={'padding': 10, 'flex': 1})
    ],
        style={'display': 'flex', 'flexDirection': 'row'}
    )
    return components_1


def register_layout_query():
    component_1 = dash_components()

    # visualização 3
    q3 = [
        dbc.Row(
            children=[
                html.H1(
                    children="View 3 - More details by CVE",
                    style={'text-align': 'center'}
                ),
                html.H2(
                    children="This visualization allows the analysis of the distribution of CVEs "
                                 "in relation to IPs and organizations acessible on the Internet",
                        style={'font-size': '20px'}
                ),

                component_1,

                dbc.Row(
                    dash_table.DataTable(
                        id='query-3-table',
                        columns=[
                            {"name": "CVE", "id": "cve_id", "selectable": True},
                            {"name": "CVSS", "id": "cvss", "selectable": True}, # TODO {CVSS and CVSS Rank}
                            {"name": "CVSS Rank", "id": "cvss_rank", "selectable": True},
                            {"name": "CVSS Version", "id": "cvss_version", "selectable": True},
                            {"name": "EPSS Rank", "id": "epss_rank", "selectable": True},
                            {"name": "# IPs", "id": "n_ips", "selectable": True},
                            {"name": "# Organizations", "id": "n_orgs", "selectable": True},
                        ],
                        editable=True,
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        row_selectable='multi',
                        page_current=0,
                        page_size=15,
                        style_data={
                            'whiteSpace': 'normal',
                            'max-height': '15px',
                            'min-height': '15px',
                            'height': '15px'
                        }
                    ),
                    style={'margin-top': '32px'}
                ),

                html.H4(children="Choose the type of visualization based on the y-axis.", style={'text-align': 'Left'}),

                dbc.Row(
                    dcc.Dropdown(
                        id='graph-type',
                        options=[
                            {'label': 'EPSS Rank', 'value': 'epss_rank'},
                            {'label': '# IPS', 'value': 'n_ips'},
                            {'label': '# Organizations', 'value': 'n_orgs'},
                        ],
                        value='epss_rank'
                    ),
                    style={'margin-top': '32px'}
                ),

                html.Div(id='datable-interactivity-container'),
            ]
        ),
    ]

    return q3

def register_callback_query(app):
    @app.callback(
        Output('query-3-table', "data"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by"),
        Input('search-bar-cve', 'value'),
        Input('dropdown-cvss-version', 'value'),
        Input('cvss-range-slider', 'value'),
        Input('epss-range-slider', 'value'),
        Input('search-bar-org', 'value'),
        Input('search-bar-ip', 'value')

    )
    def update_table3(date_value, sort_by, ip_query, cve_query, dropdown_query, org_query,
                      cvss_query, epss_query):
        print("[INFO] query 3 - update_table3: ", date_value)

        df = base.get_dataset(date_value, INPUT_DATA).drop(['org_list'], axis=1).drop_duplicates(["cve_id"])

        df['cvss_version'] = df['cvss_version'].astype(float)

        if len(sort_by):
            df = df.sort_values(
                [col['column_id'] for col in sort_by],
                ascending=[
                    col['direction'] == 'asc'
                    for col in sort_by
                ],
                inplace=False
            )

        # if ip_query:
        #     op = str(ip_query)
        #     operator = op[0]
        #     value = op[1:].strip()
        #     value = int(value)
        #     if operator == '=':
        #         df = df[df['n_ips'] == value]
        #     elif operator == '!=':
        #         df = df[df['n_ips'] != value]
        #     elif operator == '>':
        #         df = df[df['n_ips'] > value]
        #     elif operator == '<':
        #         df = df[df['n_ips'] < value]
        #     elif operator == '>=':
        #         df = df[df['n_ips'] >= value]
        #     elif operator == '<=':
        #         df = df[df['n_ips'] <= value]

        if cve_query:
            df = df[df['cve_id'].str.contains(cve_query, case=False)]

        if dropdown_query:
            drop = str(dropdown_query)
            numbers = json.loads(drop)
            value1 = float(numbers[0])
            value2 = float(numbers[1])
            df = df[(df['cvss_version'] >= value1) & (df['cvss_version'] <= value2)]

        # if org_query:
        #     op = str(org_query)
        #     operator = op[0]
        #     value = op[1:].strip()
        #     value = int(value)
        #     if operator == '=':
        #         df = df[df['n_ors'] == value]
        #     elif operator == '!=':
        #         df = df[df['n_ors'] != value]
        #     elif operator == '>':
        #         df = df[df['n_ors'] > value]
        #     elif operator == '<':
        #         df = df[df['n_ors'] < value]
        #     elif operator == '>=':
        #         df = df[df['n_orgs'] >= value]
        #     elif operator == '<=':
        #         df = df[df['n_orgs'] <= value]

        if cvss_query:
            df = df[(df['cvss'] >= cvss_query[0]) & (df['cvss'] <= cvss_query[1])]

        return df.to_dict('records')

    @app.callback(
        Output('query-3-table', "style_data_conditional"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by")
    )
    def update_styles(date_value, sort_by):
        print("[INFO] query 3 - update_styles: ", date_value)
        df = base.get_dataset(date_value, INPUT_DATA)

        return [{
            'if': {'column_id': i['column_id']},
            'background_color': 'white'
        } for i in sort_by]

    # @app.callback(
    #     Output('datable-interactivity-container', "children"),
    #     Input('date-picker-single', 'date'),
    #     Input('query-3-table', "derived_virtual_data"),
    #     Input('query-3-table', "derived_virtual_selected_rows"),
    #     Input('graph-type', 'value'),
    # )
    # def update_graphs(date_value, rows, derived_virtual_selected_rows, value, page_current):
    #     print("[INFO] update_graphs: ", date_value)
    #     df = base.get_dataset(date_value, INPUT_DATA)



# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: apenas ao clicar ? por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer ?


# def create_legend_table():
#     columns_type = ["Equal", "Greater than", "Less than", "Not equal"]
#     columns_cve_id = ["CVE-2022-3ee1 or CVE-2022 or 2022-3ee1 or 2022", "< CVE-2022-3ee1 or < CVE-2022",
#                       "> CVE-2022-3ee1 or > CVE-2022, ", "!= CVE-2022-3ee1"]
#     columns_cvss = ["= 2.5", "< 2.5", "> 2.5", "!= 2.5"]
#     columns_cvss_rank = ["= 0.4", "< 0.4", "> 0.4", "!= 0.4"]
#     columns_cvss_version = ["= 2.1", "< 2.1", "> 2.1", "!= 2.1"]
#     columns_epss_rank = ["= 0.6", "< 0.6", "> 0.6", "!= 0.6"]
#     columns_ips = ["= 44", "< 44", "> 44", "!= 44"]
#     columns_orgs = ["= 678", "< 678", "> 678", "!= 678"]
#
#     data = []
#     for i in range(len(columns_type)):
#         data.append({
#             "type": columns_type[i],
#             "cve_id": columns_cve_id[i],
#             "cvss": columns_cvss[i],
#             "cvss_rank": columns_cvss_rank[i],
#             "cvss_version": columns_cvss_version[i],
#             "epss_rank": columns_epss_rank[i],
#             "ips": columns_ips[i],
#             "orgs": columns_orgs[i],
#         })
#
#     legend_table = dash_table.DataTable(
#
#         id='legend-table',
#         columns=[
#             {"name": ["Type"], "id": "type"},
#             {"name": ["CVE ID"], "id": "cve_id"},
#             {"name": ["CVSS"], "id": "cvss"},
#             {"name": ["CVSS Rank"], "id": "cvss_rank"},
#             {"name": ["CVSS Version"], "id": "cvss_version"},
#             {"name": ["EPSS Rank"], "id": "epss_rank"},
#             {"name": ["# IPS"], "id": "ips"},
#             {"name": ["# Organizations"], "id": "orgs"},
#         ],
#         data=data,
#     )
#
#     return legend_table
#
#
# def register_layout_query():
#     legend_table = create_legend_table()
#     # visualização 3
#     q3 = [
#         dbc.Row(
#             children=[
#                 html.H1(children="View 3 - More details by CVE", style={'text-align': 'center'}),
#                 html.H2(children="This analysis allows filtering the desired data in the table "
#                                  "and generating a chart related to the chosen information.",
#                         style={'font-size': '20px'}),
#                 dbc.Col(
#                     children=[
#                         html.H1(children="DataTable Filtering", style={'font-size': '15px'})
#                     ],
#                     width=4
#                 ),
#                 # Tabela Legenda
#                 dbc.Row(
#                     html.Div(
#                         children=[
#                             legend_table,
#                         ],
#                         style={
#                             'whiteSpace': 'normal',
#
#                         }
#                     ),
#                 ),
#                 # Tabela interativa
#                 dbc.Row(
#                     # Renders an interactive table component
#                     dash_table.DataTable(
#
#                         id='query-3-table',
#                         columns=[
#                             {"name": "CVE", "id": "cve_id", "selectable": True, "deletable": True},
#                             {"name": "CVSS", "id": "cvss", "selectable": True, "deletable": True},
#                             {"name": "CVSS Rank", "id": "cvss_rank", "selectable": True, "deletable": True},
#                             {"name": "CVSS Version", "id": "cvss_version", "selectable": True, "deletable": True},
#                             {"name": "EPSS Rank", "id": "epss_rank", "selectable": True, "deletable": True},
#                             {"name": "# IPs", "id": "n_ips", "selectable": True, "deletable": True},
#                             {"name": "# Organizations", "id": "n_orgs", "selectable": True, "deletable": True},
#                         ],
#                         editable=True,
#                         filter_action="native",
#                         sort_action='custom',
#                         sort_mode='multi',
#                         sort_by=[],
#                         row_selectable='multi',
#                         row_deletable=True,
#                         page_current=0,
#                         page_size=15,
#                         style_data={
#                             'whiteSpace': 'normal',
#                             'height': 'auto',
#                             'max-height': '15px', 'min-height': '15px', 'height': '15px'
#                         }
#                     ),
#                     style={'margin-top': '32px'}
#
#                 ),
#
#                 html.H4(children="Choose the type of visualization based on the y-axis.", style={'text-align': 'Left'}),
#                 # Dropdown selecionar gráfico
#                 dbc.Row(
#                     dcc.Dropdown(
#                         id='graph-type',
#                         options=[
#                             {'label': 'EPSS Rank', 'value': 'epss_rank'},
#                             {'label': '# IPS', 'value': 'n_ips'},
#                             {'label': '# Organizations', 'value': 'n_orgs'},
#                         ],
#                         value='epss_rank'
#                     ),
#                     style={'margin-top': '32px'}
#                 ),
#
#                 html.Div(id='datable-interactivity-container'),
#             ]
#         ),
#     ]
#
#     return q3
#
#
# def register_callback_query(app):
#     @app.callback(
#         Output('query-3-table', "data"),
#         Input('date-picker-single', 'date'),
#         Input('query-3-table', "sort_by")
#     )
#     def update_table3(date_value, sort_by):
#         print("[INFO] query 3 - update_table3: ", date_value)
#
#         df = base.get_dataset(date_value, INPUT_DATA).drop(['org_list'], axis=1)
#
#         df['cvss_version'] = df['cvss_version'].astype(float)
#
#         df["cvss_rank"] = [float(str(i).replace("<", "").replace(">", "").replace("=", ""))
#                            for i in df["cvss_rank"]]
#
#         df["epss_rank"] = [float(str(i).replace("<", "").replace(">", "").replace("=", ""))
#                            for i in df["epss_rank"]]
#
#         if len(sort_by):
#             df = df.sort_values(
#                 [col['column_id'] for col in sort_by],
#                 ascending=[
#                     col['direction'] == 'asc'
#                     for col in sort_by
#                 ],
#                 inplace=False
#             )
#
#         return df.to_dict('records')
#
#     @app.callback(
#         Output('query-3-table', "style_data_conditional"),
#         Input('date-picker-single', 'date'),
#         Input('query-3-table', "sort_by")
#     )
#     def update_styles(date_value, sort_by):
#         print("[INFO] query 3 - update_styles: ", date_value)
#         df = base.get_dataset(date_value, INPUT_DATA)
#
#         return [{
#             'if': {'column_id': i['column_id']},
#             'background_color': 'white'
#         } for i in sort_by]
#
#     @app.callback(
#         Output('datable-interactivity-container', "children"),
#         Input('date-picker-single', 'date'),
#         Input('query-3-table', "derived_virtual_data"),
#         Input('query-3-table', "derived_virtual_selected_rows"),
#         Input('graph-type', 'value'),
#         Input('query-3-table', "page_current")
#     )
#     def update_graphs(date_value, rows, derived_virtual_selected_rows, value, page_current):
#         print("[INFO] update_graphs: ", date_value)
#         df = base.get_dataset(date_value, INPUT_DATA)
#
#         df_table = df.copy()
#
#         # rows -> uma var que armazena as linhas de uma tabela que foram alteradas ou selecionadas
#         if rows is not None:
#             df_selected_rows = pd.DataFrame(rows)
#             df_table.update(df_selected_rows)
#
#         # derivered_virtual.... -> contém os índices das linhas que foram selecionadas
#         if derived_virtual_selected_rows is None:
#             derived_virtual_selected_rows = []
#
#         # mudar o gráfico conforme há mudança de página
#         start = page_current*15
#         end = (page_current+1)*15
#
#         # reset_index() -> redefine os índices de um df após x op. que alteram esses
#         df_subset = df_table.iloc[start:end]
#
#         colors = ['red' if i in derived_virtual_selected_rows else 'blue'
#                   for i in range(len(df_subset))]
#
#         graphs = []
#         if value in df_subset:
#             if value == "epss_rank":
#                 fig = px.scatter(df_subset, x="cve_id", y=df_subset[value], marginal_x="histogram", marginal_y="rug", color=colors)
#                 fig.update_layout(
#                     xaxis_title = "CVE ID",
#                     yaxis_title = "EPSS Rank",
#                     xaxis=dict(showticklabels=False),
#                 )
#                 graphs.append(
#                     dcc.Graph(
#                         id=value,
#                         figure=fig
#                 ))
#             else:
#                 df_grouped = df_subset.groupby('cve_id')[value].agg(['min', 'max', 'mean']).reset_index()
#
#                 fig = go.Figure([
#                     go.Scatter(
#                         name='Measurement',
#                         x=df_grouped['cve_id'],
#                         y=df_grouped['mean'],
#                         mode='markers',
#                         #"#FF8849"
#                         marker=dict(color=colors, size=10),
#                         showlegend=True
#                     ),
#                     go.Scatter(
#                         name='Upper Bound',
#                         x=df_grouped['cve_id'],
#                         y=df_grouped['max'],
#                         mode='lines',
#                         marker=dict(color="#ee6c4d"),
#                         line=dict(width=1),
#                         showlegend=True
#                     ),
#                     go.Scatter(
#                         name='Lower Bound',
#                         x=df_grouped['cve_id'],
#                         y=df_grouped['min'],
#                         marker=dict(color="#3d5a80"),
#                         line=dict(width=1),
#                         mode='lines',
#                         fillcolor='rgba(68, 68, 68, 0.3)',
#                         fill='tonexty',
#                         showlegend=True
#                     )
#                 ])
#
#                 if value == "n_ips":
#                     fig.update_layout(
#                         xaxis_title = "CVE ID",
#                         yaxis_title=f'# IPs',
#                         title=f'Number of IPs per CVE ID',
#                         hovermode="x",
#                         xaxis=dict(showticklabels=False)
#                     )
#                 else:
#                     fig.update_layout(
#                         xaxis_title = "CVE ID",
#                         yaxis_title=f'# Organizations',
#                         title=f'Number of organizations per CVE ID',
#                         hovermode="x",
#                         xaxis=dict(showticklabels=False)
#                     )
#
#                 graphs.append(dcc.Graph(
#                     id=value,
#                     figure=fig
#                 ))
#
#         return graphs

