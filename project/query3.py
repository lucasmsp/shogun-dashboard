import project.base as base
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output

INPUT_DATA = '3'

# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: apenas ao clicar ? por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer ?

# gráficos CVE x N_orgs, CVE X N_ips, CVE X EPSS
# constructs the layout for View 3
def create_legend_table():

    columns_type = ["Equal", "Greater than", "Less than", "Not equal"]
    columns_cve_id = ["CVE-2022-3ee1 or CVE-2022 or 2022-3ee1 or 2022", "< CVE-2022-3ee1 or < CVE-2022",
                      "> CVE-2022-3ee1 or > CVE-2022, ", "!= CVE-2022-3ee1"]
    columns_cvss = ["= 2.5", "< 2.5", "> 2.5" , "!= 2.5"]
    columns_cvss_rank = ["= 0.4", "< 0.4", "> 0.4" , "!= 0.4"]
    columns_cvss_version = ["= 2.1", "< 2.1", "> 2.1", "!= 2.1"]
    columns_epss_rank = ["= 0.6", "< 0.6", "> 0.6", "!= 0.6"]
    columns_ips = ["= 44", "< 44", "> 44", "!= 44"]
    columns_orgs = ["= 678", "< 678", "> 678", "!= 678"]

    data = []
    for i in range(len(columns_type)):
        data.append({
            "type": columns_type[i],
            "cve_id": columns_cve_id[i],
            "cvss": columns_cvss[i],
            "cvss_rank": columns_cvss_rank[i],
            "cvss_version": columns_cvss_version[i],
            "epss_rank": columns_epss_rank[i],
            "ips": columns_ips[i],
            "orgs": columns_orgs[i],
        })

    legend_table = dash_table.DataTable(

        id='legend-table',
        columns = [
               {"name": ["Type"], "id": "type"},
               {"name": ["CVE ID"], "id": "cve_id"},
               {"name": ["CVSS"], "id": "cvss"},
               {"name": ["CVSS Rank"], "id": "cvss_rank"},
               {"name": ["CVSS Version"], "id": "cvss_version"},
               {"name": ["EPSS Rank"], "id": "epss_rank"},
               {"name": ["# IPS"], "id": "ips"},
               {"name": ["# Organizations"], "id": "orgs"},
            ],
            data = data,
    )

    return legend_table

def register_layout_query():
    legend_table = create_legend_table()
    # visualização 3
    q3 = [
        dbc.Row(
            children=[
                html.H1(children="View 3 - More details by CVE", style={'text-align': 'center'}),
                html.H2(children="This analysis allows filtering the desired data in the table "
                                 "and generating a chart related to the chosen information.",
                        style={'font-size': '20px'}),
                dbc.Col(
                    children=[
                        html.H1(children="DataTable Filtering", style={'font-size': '15px'})
                    ],
                    width=4
                ),

                dbc.Row(
                    html.Div(
                        children=[
                            legend_table,
                        ],
                        style={
                            'whiteSpace': 'normal',

                        }
                    ),
                ),
                # contém uma tabela iterativa Dash
                dbc.Row(
                    # Renders an interactive table component
                    dash_table.DataTable(

                        id='query-3-table',
                        columns=[
                            {"name": "CVE", "id": "cve_id", "selectable": True, "deletable": True},
                            {"name": "CVSS", "id": "cvss", "selectable": True, "deletable": True},
                            {"name": "CVSS Rank", "id": "cvss_rank", "selectable": True, "deletable": True},
                            {"name": "CVSS Version", "id": "cvss_version", "selectable": True, "deletable": True},
                            {"name": "EPSS Rank", "id": "epss_rank", "selectable": True, "deletable": True},
                            {"name": "# IPs", "id": "n_ips", "selectable": True, "deletable": True},
                            {"name": "# organizations", "id": "n_orgs", "selectable": True, "deletable": True},
                        ],
                        # permite que a tabela seja editável
                        editable=True,
                        # permite filtragem da tabela
                        filter_action="native",
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        row_selectable='multi',
                        row_deletable=True,
                        page_current=0,
                        page_size=15,
                        style_data={
                            'whiteSpace': 'normal',
                            'height': 'auto',
                            'max-height': '15px', 'min-height': '15px', 'height': '15px'
                        }
                    ),
                    style={'margin-top': '32px'}

                ),
                html.Div(id='datable-interactivity-container'),
            ]
        ),
    ]

    return q3

# register all the callbacks in one place
def register_callback_query(app):
    @app.callback(
        Output('query-3-table', "data"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by")
    )
    def update_table3(date_value, sort_by):
        print("[INFO] query 3 - update_table3: ", date_value)

        df = base.get_dataset(date_value, INPUT_DATA).drop(['org_list'], axis=1)

        df['cvss_version'] = df['cvss_version'].astype(float)

        df["cvss_rank"] = [float(str(i).replace("<", "").replace(">", "").replace("=", ""))
                           for i in df["cvss_rank"]]

        df["epss_rank"] = [float(str(i).replace("<", "").replace(">", "").replace("=", ""))
                           for i in df["epss_rank"]]

        if len(sort_by):
            df = df.sort_values(
                [col['column_id'] for col in sort_by],
                ascending=[
                    col['direction'] == 'asc'
                    for col in sort_by
                ],
                inplace=False
            )

        return df.to_dict('records')

    @app.callback(
        Output('query-3-table', "style_data_conditional"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "sort_by")
    )

    def update_styles(date_value, sort_by):
        print("[INFO] query 3 - update_styles: ", date_value)
        df = base.get_dataset(date_value, INPUT_DATA)

        return[{
            'if': {'column_id': i['column_id']},
            'background_color': 'white'
        } for i in sort_by]

    @app.callback(
        Output('datable-interactivity-container', "children"),
        Input('date-picker-single', 'date'),
        Input('query-3-table', "derived_virtual_data"),
        Input('query-3-table', "derived_virtual_selected_rows")
    )
    def update_graphs(date_value, rows, derived_virtual_selected_rows):
        print("[INFO] update_graphs: ", date_value)
        df = base.get_dataset(date_value, INPUT_DATA)

        if derived_virtual_selected_rows is None:
            derived_virtual_selected_rows = []

        colors = ['red' if i in derived_virtual_selected_rows else '#0074D9'
                  for i in range(len(df))]

        return [
            dcc.Graph(
                id=column,
                figure={
                    "data": [
                        {
                            "x": df["cve_id"],
                            "y": df[column],
                            # "type": "barh",
                            "mode": "markers",
                            "marker": {
                                "color": colors,
                                "size": 10,
                                "opacity": 0.8,
                                "line": {"width": 0.5, "color": "white"}
                            },
                        }
                    ],
                    "layout": {
                        "xaxis": {"automargin": True},
                        "yaxis": {
                            "automargin": True,
                            "title": {"text": column}
                        },
                        "height": 200,
                        "margin": {"t": 10, "l": 10, "r": 10},
                    },
                },
            )
            for column in ["cvss", "cvss_rank", "cvss_version", "epss_rank", "n_ips", "n_orgs"] if column in df
        ]
