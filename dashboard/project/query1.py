from dash import html, dcc
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input

import plotly.express as px
import dash_ag_grid as dag

from project.auxiliar import gen_subgraphs, header_mapping

INPUT_DATA = '1'

def register_layout_query(filter_modal={}):
    elements = [
        html.H1(children="View 1 - EPSS summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
                dbc.Row(
                    dag.AgGrid(
                        id='query-1-table',
                        columnDefs=[
                            {"field": "vulns_epss_rank", "headerName": header_mapping['epss_rank']['name'], "flex": 1,
                             'headerTooltip': header_mapping['epss_rank']['description']},
                            {"field": 'n_cves', "headerName": header_mapping['n_cves']['name'], "flex": 1,
                             'headerTooltip': header_mapping['n_cves']['description']},
                            {"field": 'n_ips', "headerName": header_mapping['n_ips']['name'], "flex": 1,
                             'headerTooltip': header_mapping['n_ips']['description']},
                            {"field": 'n_orgs', "headerName": header_mapping['n_orgs']['name'], "flex": 1,
                             'headerTooltip': header_mapping['n_orgs']['description']},
                            {"field": "n_as", "headerName": header_mapping['n_as']['name'], "flex": 1,
                             'headerTooltip': header_mapping['n_as']['description']},
                        ],
                        rowData = [{"vulns_epss_rank": "Processing...", "n_cves": 0, "n_ips": 0, "n_orgs": 0, 'n_as': 0}],
                        defaultColDef={"flex": 1, "resizable": False},
                        columnSize="responsiveSizeToFit",
                        columnSizeOptions= {"skipHeader": False},
                        dashGridOptions={"animateRows": False},
                        style={"height": 260}
                    ),
                ),
                dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
                dbc.Row([html.Div(id='query-1-graph', children=[])]
                )
            ]
        )
    ]

    tab1_content = dbc.Card(
            dbc.CardBody(html.Div(children=[dbc.Row(children=elements)], className="wrapper")),
            className="mt-3",
            id="tab1_content"
    )
    
    return tab1_content



def register_callback_query(dm, app):
    @app.callback(
        Output('query-1-table', "rowData"),
        Input('date-picker-single', 'value')
    )
    def update_table1(date_value):
        print(f"[INFO][query1] update_table1: {date_value}")
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        return df.to_dict('records')


    @app.callback(
        Output("query-1-graph", "children"),
        Input('date-picker-single', 'value')
    )
    def update_chart1(date_value):

        print(f"[INFO][query1] update_chart1: {date_value}")

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return []

        graphs_type = {
            "Bar plot - Number of CVEs by EPSS Rank":
                { "y_column": "n_cves", "graph_type": "bar plot", "y_label": "# CVEs",
                  'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "Bar plot - Number of organizations by EPSS Rank":
                {"y_column": "n_orgs", "graph_type": "bar plot", "y_label": "# Orgs",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "Bar plot - Number of IPs by EPSS Rank":
                {"y_column": "n_ips", "graph_type": "bar plot", "y_label": "# IPs",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "PDF plot - Number of CVEs by EPSS Rank":
                {"y_column": "n_cves", "graph_type": "pdf plot", "y_label": "# CVEs",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "CDF plot - Number of CVEs by EPSS Rank":
                {"y_column": "n_cves", "graph_type": "cdf plot", "y_label": "# CVEs",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

        }

        graphs = []
        for title, configs in graphs_type.items():
            y_column = configs['y_column']
            x_column = configs['x_column']
            y_label = configs['y_label']
            x_label = configs['x_label']
            graph_type = configs['graph_type']

            if graph_type == "bar plot":
                fig = px.bar(df,
                             x=x_column,
                             y=y_column,
                             barmode="group",
                             labels={
                                 x_column: x_label,
                                 y_column: y_label
                             },
                             title= title
                )

            elif graph_type == "pdf plot":
                df['pdf'] = df[y_column] / sum(df[y_column])
                df = df.reset_index()
                fig = px.line(df,
                              x=x_column,
                              y='pdf',
                              range_y=(0, 1),
                              title= title,
                              labels={
                                  x_column: x_label,
                                  'pdf': "PDF"
                              }
                )

            else:
                df['pdf'] = df[y_column] / sum(df[y_column])
                df['cdf'] = df['pdf'].cumsum()
                df = df.reset_index()
                fig = px.line(df,
                              x=x_column,
                              y='cdf',
                              range_y=(0, 1),
                              title= title,
                              labels={
                                  x_column: x_label,
                                  'cdf': "CDF"
                              }
                )

            graph = dcc.Graph(figure=fig,
                              config={
                                  'displayModeBar': False,
                                  'scrollZoom': False
                              }
            )
            graphs.append(graph)

        children = gen_subgraphs(n_cols=3, graphs=graphs)

        return children




