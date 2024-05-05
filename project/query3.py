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
                marks={
                    0.0: '0.0',
                    0.2: '0.2',
                    0.4: '0.4',
                    0.6: '0.6',
                    0.8: '0.8',
                    1.0: '1.0',
                },
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
                            {"name": "CVSS", "id": "cvss", "selectable": True},  # TODO {CVSS and CVSS Rank}
                            {"name": "CVSS Rank", "id": "cvss_rank", "selectable": True},
                            {"name": "CVSS Version", "id": "cvss_version", "selectable": True},
                            {"name": "EPSS Rank", "id": "epss_rank", "selectable": True},
                            {"name": "# IPs", "id": "n_ips", "selectable": True},
                            {"name": "# Organizations", "id": "n_orgs", "selectable": True},
                        ],
                        # editable=True,
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

def find_expression(string):
    list_expressions = ['>=', '<=', '!=']
    for i in list_expressions:
        index = string.find(i)

        if index != -1:
            return i


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
    def update_table3(date_value, sort_by, cve_query, dropdown_query_cvss, cvss_range_query,
                      epss_range_query, org_query, ip_query):
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

        if cve_query:
            df = df[df['cve_id'].str.contains(cve_query, case=False)]

        if dropdown_query_cvss:
            drop = str(dropdown_query_cvss)
            value = float(drop)
            df = df[df['cvss_version'] == value]

        if cvss_range_query:
            df = df[(df['cvss'] >= cvss_range_query[0]) & (df['cvss'] <= cvss_range_query[1])]

        if org_query:
            op = str(org_query)
            op = op.replace(" ", "")
            result_expression = find_expression(op)

            if result_expression in ['>=', '<=', '!=']:
                info = op.split('=')
                value = int(info[1])
                if result_expression == ">=":
                    df = df[df['n_orgs'] >= value]

                elif result_expression == '<=':
                    df = df[df['n_orgs'] <= value]

                elif result_expression == '!=':
                    df = df[df['n_orgs'] != value]

            else:
                operator = op[0]
                value = op[1:].strip()
                value = int(value)
                if operator == '=':
                    df = df[df['n_orgs'] == value]
                elif operator == '>':
                    df = df[df['n_orgs'] > value]
                elif operator == '<':
                    df = df[df['n_orgs'] < value]

        if ip_query:
            op = str(ip_query)
            op = op.replace(" ", "")
            result_expression = find_expression(op)

            if result_expression in ['>=', '<=', '!=']:
                info = op.split('=')
                value = int(info[1])
                if result_expression == ">=":
                    df = df[df['n_ips'] >= value]

                elif result_expression == '<=':
                    df = df[df['n_ips'] <= value]

                elif result_expression == '!=':
                    df = df[df['n_ips'] != value]

            else:
                operator = op[0]
                value = op[1:].strip()
                value = int(value)
                if operator == '=':
                    df = df[df['n_ips'] == value]
                elif operator == '>':
                    df = df[df['n_ips'] > value]
                elif operator == '<':
                    df = df[df['n_ips'] < value]

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
