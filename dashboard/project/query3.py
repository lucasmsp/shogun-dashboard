import itertools

from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output

import plotly.express as px
import plotly.figure_factory as ff

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
                    "marginLeft": "30px",
                    "marginBottom": "10px",
                }
            ),
            dcc.RangeSlider(
                id='cvss-range-slider',
                min=0,
                max=10,
                count=1,
                value=[0, 10],
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
                    id='search-bar-query3-org',
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
                    id='search-bar-query3-ip',
                    type="search",
                    placeholder="IP filter expression ('>', '<', '=','>=', '<=') e.g., '> 30'",
                    style={
                        "width": "100%",
                        "margin": "15px"
                    }
                )
            ]),

            html.Label(
                children='Choose the EPSS range',
                style={
                    "marginLeft": "30px",
                }
            ),
            dcc.RangeSlider(
                id='epss-range-query3-slider',
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
                value=[0, 1],
                tooltip={
                    'placement': 'top',
                    'always_visible': True,
                },
                allowCross=False,
            ),
        ],
            style={'padding': 10, 'flex': 1})
    ],
        style={'display': 'flex', 'flexDirection': 'row'}
    )
    return components_1


#constructs the layout for View 3
def register_layout_query(dm):
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
                             "in relation to IPs and organizations accessible on the Internet",
                    style={'font-size': '20px'}
                ),

                component_1,

                dbc.Row(
                    dash_table.DataTable(
                        id='query-3-table',
                        columns=[
                            {"name": "CVE", "id": "cve_id", "selectable": True},
                            {"name": "CVSS", "id": "cvss_score", "selectable": True},
                            {"name": "EPSS Rank", "id": "epss_rank", "selectable": True},
                            {"name": "# IPs", "id": "n_ips", "selectable": True},
                            {"name": "# Organizations", "id": "n_orgs", "selectable": True},
                        ],
                        active_cell={'row': 0, 'column': 0, 'column_id': 'cve_id'},
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        page_current=0,
                        page_size=15,
                        style_data={
                            'whiteSpace': 'normal',
                            'max-height': '15px',
                            'min-height': '15px',
                            'height': '15px'
                        }
                    ),
                    style={'marginTop': '32px'}
                ),

                html.H5(children="For more information's about the CVE, click in the link bellow",
                        style={'text-align': 'Left'}),

                html.A(id='link', target='_blank'),

                html.Div(style={'height': '50px'}),

                dbc.Popover([
                    dbc.PopoverHeader("Título do Popover"),
                    dbc.PopoverBody("Conteúdo do Popover"),
                ], id="popover-query3"),

                html.H4(children="Choose the type of chart", style={'text-align': 'Left'}),
                dbc.Row(
                    dcc.Dropdown(
                        id='graph-type',
                        options=[
                            {'label': 'Scatter plot - EPSS by CVSS Score', 'value': 'epss_cvss'},
                            {'label': 'Confusion Matrix - EPSS Rank by CVSS Rank', 'value': 'epss_rank_cvss_rank'},
                            {'label': 'Line plot - # IPS by CVSS', 'value': 'ips_cvss'},
                            {'label': 'Line plot - # IPs by EPSS', 'value': 'ips_epss'},
                            {'label': 'Line plot - # Organizations by CVSS', 'value': 'orgs_cvss'},
                            {'label': "Line plot - # Organizations by EPSS", 'value': 'orgs_epss'},
                        ],
                        value=''
                    ),
                    style={'marginTop': '32px'}
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


def get_tooltip_info(row):
    return "".join(["| " + i + " | " + j + " | \n"
                    for i, j in itertools.zip_longest(
            str(row["cvss_version"]).split(";")[0:20],
            str(row["cvss_rank"]).split(";")[0:20], fillvalue=" ")])


# register all the callbacks in one place
def register_callback_query(dm, app):
    @app.callback(
        Output('link', 'href'),
        Output('link', 'children'),
        Output('query-3-table', "data"),
        Output('query-3-table', "tooltip_data"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by"),
        Input('query-3-table', 'active_cell'),
        Input('search-bar-cve', 'value'),
        Input('dropdown-cvss-version', 'value'),
        Input('cvss-range-slider', 'value'),
        Input('epss-range-query3-slider', 'value'),
        Input('search-bar-query3-org', 'value'),
        Input('search-bar-query3-ip', 'value')
    )
    def update_table3(date_value, sort_by, active_cell, cve_query, dropdown_query_cvss, cvss_range_query,
                      epss_range_query, org_query, ip_query):
        print("[INFO] query 3 - update_table3: ", date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        # df['cvss_and_cvssv'] = df['cvss_score'].astype(str) + ' (v ' + df['cvss_version'].astype(str) + ')'
        #df['cvss_version'] = df['cvss_version'].astype(float)
        #df['cvss_score'] = df['cvss_score'].astype(float)


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
            df = df[(df['cvss_score'] >= cvss_range_query[0]) & (df['cvss_score'] <= cvss_range_query[1])]

        if epss_range_query:
            df = df[(df['epss'] >= epss_range_query[0]) & (df['epss'] <= epss_range_query[1])]

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

        tooltip_data = [
            {
                'cvss_score': {
                    'value':
                        "| CVSS Version         |  CVSS Rank           |  \n" +
                        "| :------------------: | :------------------: |  \n" +
                        get_tooltip_info(row),
                    'type': 'markdown'
                },
                'epss_rank': {
                    'value': "**EPSS:**  " + str(row['epss']),
                    'type': 'markdown'
                },
            } for row in df.to_dict('records')
        ]

        if active_cell:
            row = active_cell['row']
            col = active_cell['column_id']
            cell_value = df.iloc[row][col]
            if col == 'cve_id':
                url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cell_value}"
                return url, f"{url}", df.to_dict('records'), tooltip_data

        # default value for the cve
        first_cve_value = df.iloc[0]['cve_id']
        url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={first_cve_value}"
        return url, f"{url}", df.to_dict('records'), tooltip_data

        # return '', '', df.to_dict('records'), tooltip_data
        # return df.to_dict('records'), tooltip_data

    @app.callback(
        Output('query-3-table', "style_data_conditional"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by")
    )
    def update_styles(date_value, sort_by):
        print("[INFO] query 3 - update_styles: ", date_value)
        return [{
            'if': {'column_id': i['column_id']},
            'background_color': 'white'
        } for i in sort_by]

    @app.callback(
        Output('datable-interactivity-container', "children"),
        Input('date-picker-single', 'date'),
        Input('graph-type', 'value')
    )
    def update_graphs(date_value, value):
        print("[INFO] update_graphs: ", date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        # print(df.dtypes)
        graphs = []

        if value:
            graphs.append(
                dcc.Graph(
                    id=value,
                    figure=get_graph(df, value)
                )
            )
        else:
            graphs.append(
                dcc.Graph(
                    id='epss_cvss',
                    figure=get_graph(df, 'epss_cvss')
                )
            )

        return graphs

    def get_graph(df, value):

        if value == "epss_cvss":
            fig = px.scatter(df, x=df["cvss_score"], y=df['epss'], title="Scatter plot - EPSS by CVSS score",
                             color='epss_rank')
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="EPSS",
                # xaxis=dict(showticklabels=False),
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            return fig

        elif value == "epss_rank_cvss_rank":
            z = df.groupby(["cvss_rank", "epss_rank"]).count() \
                .reset_index() \
                .pivot(index="cvss_rank", columns="epss_rank", values=["cve_id"]) \
                .fillna(0) \
                .reset_index()
            z.columns = ['epss_rank', '< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']

            severity_mapping = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4
            }
            z['severity'] = z['epss_rank'].map(severity_mapping)
            z = z.sort_values(by='severity', ascending=True)

            x = ["low", "medium", "high", "critical"]
            y = ['< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']
            z = z[y].T.values.tolist()
            z_text = [[str(y) for y in x] for x in z]

            fig = ff.create_annotated_heatmap(z, x=x, y=y, annotation_text=z_text, colorscale='Viridis')
            fig['data'][0]['showscale'] = True

            fig.update_layout(
                height=600,
                width=600,
                title_text='Confusion Matrix - EPSS Rank by CVSS Rank',
                xaxis_title="CVSS Rank",
                yaxis_title="EPSS Rank",
                xaxis={'side': 'bottom'},
            )
            return fig
        elif value == "ips_cvss":
            df = df.groupby("cvss_score").sum("n_ips").reset_index()
            fig = px.line(df, x=df['cvss_score'], y=df['n_ips'], title="Line plot - # IPs by CVSS")
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="# IPs",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            return fig

        elif value == "orgs_cvss":
            df = df.groupby("cvss_score").sum("n_orgs").reset_index()
            fig = px.line(df, x=df['cvss_score'], y=df['n_orgs'], title="Line plot - # Organizations by CVSS")
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="# Organizations",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            return fig

        elif value == "orgs_epss":
            df = df.groupby("epss").sum("n_orgs").reset_index()
            fig = px.line(df, x=df['epss'], y=df['n_orgs'], title="Line plot - # Organizations by EPSS")
            fig.update_layout(
                xaxis_title="EPSS Score",
                yaxis_title="# Organizations",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    range=[0, 1.0]
                )
            )
            return fig

        elif value == "ips_epss":
            df = df.groupby("epss").sum("n_ips").reset_index()
            fig = px.line(df, x=df['epss'], y=df['n_ips'], title="Line plot - # IPs by EPSS")
            fig.update_layout(
                xaxis_title="# EPSS Score",
                yaxis_title="# IPs",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    range=[0, 1.0]
                )
            )

            return fig
