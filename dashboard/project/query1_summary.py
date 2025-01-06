from dash import html, dcc, no_update
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input, State

import plotly.express as px
import plotly.graph_objs as go
import dash_ag_grid as dag

from project.auxiliar import gen_subgraphs, gen_columns_def, logging

INPUT_DATA = 'summary'

def register_layout_query(filter_modal={}):

    columns, raw_data = gen_columns_def(['vulns_epss_rank', 'n_cves', 'n_ips', 'n_orgs', 'n_as'])
    columns['n_cves']["tooltipValueGetter"] = {"function": "'Click on the cell for more details'"}

    aggrid = dag.AgGrid(
        id='query-1-table',
        columnDefs=list(columns.values()),
        rowData=raw_data,
        defaultColDef={"flex": 1, "resizable": False},
        columnSize="responsiveSizeToFit",
        columnSizeOptions={"skipHeader": False},
        dashGridOptions={"rowSelection": "single", "animateRows": False},
        style={"height": 260}
    )

    elements = [
        html.H1(children="View 1 - EPSS summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
             dbc.Row(aggrid),
             dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
             dbc.Row([html.Div(id='query-1-graph', children=[])])
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
        logging.info("update_table1: " + date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        return df.to_dict('records')


    @app.callback(
        Output("query-1-graph", "children"),
        Input('date-picker-single', 'value')
    )
    def update_chart1(date_value):
        logging.info("update_chart1: " + date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)

        if df.empty:
            return []

        graphs_type = {
            "Bar plot - Number of CVEs by EPSS Rank":
                { "y_column": "n_cves", "graph_type": "bar plot", "y_label": "# CVEs",
                  'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "CDF/PDF plot - Number of CVEs by EPSS Rank":
                {"y_column": "n_cves", "graph_type": "cdf/pdf plot", "y_label": "Probability",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},


            "Bar plot - Number of organizations by EPSS Rank":
                {"y_column": "n_orgs", "graph_type": "bar plot", "y_label": "# Orgs",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "CDF/PDF plot - Number of organizations by EPSS Rank":
                {"y_column": "n_orgs", "graph_type": "cdf/pdf plot", "y_label": "Probability",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},


            "Bar plot - Number of IPs by EPSS Rank":
                {"y_column": "n_ips", "graph_type": "bar plot", "y_label": "# IPs",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "CDF/PDF plot - Number of IPs by EPSS Rank":
                {"y_column": "n_ips", "graph_type": "cdf/pdf plot", "y_label": "Probability",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},


            "Bar plot - Number of AS by EPSS Rank":
                {"y_column": "n_as", "graph_type": "bar plot", "y_label": "# AS",
                 'x_column': 'vulns_epss_rank', 'x_label': "EPSS Rank"},

            "CDF/PDF plot - Number of AS by EPSS Rank":
                {"y_column": "n_as", "graph_type": "cdf/pdf plot", "y_label": "Probability",
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

            elif graph_type == "cdf/pdf plot":
                tmp = df.copy()
                tmp['pdf'] = tmp[y_column] / sum(df[y_column])
                tmp['cdf'] = tmp['pdf'].cumsum()
                tmp = tmp.reset_index()

                fig = go.Figure()
                fig.add_trace(go.Scatter(x=df[x_column], y=tmp['pdf'], mode='lines', name='PDF'))
                fig.add_trace(go.Scatter(x=df[x_column], y=tmp['cdf'], mode='lines', name='CDF'))
                fig.update_layout(title=title,
                                  xaxis_title=x_label,
                                  yaxis_title=y_label,
                                  showlegend=True)
            else:
                fig = go.Figure()

            graph = dcc.Graph(figure=fig,
                              config={
                                  'displayModeBar': False,
                                  'scrollZoom': False
                              }
            )
            graphs.append(graph)

        children = gen_subgraphs(n_cols=3, graphs=graphs)

        return children



    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-1-table", "cellClicked"),
        Input("query-1-table", "selectedRows"),
        prevent_initial_call=True,
    )
    def go_to_queries(cell, row):
        if cell:
            if cell.get("colId", "") == "n_cves":
                logging.info(f"Cicked cell {cell} and row {row}")
                epss_rank = row[0]['vulns_epss_rank']
                if epss_rank == "< 20":
                    filter_opt = {
                        "query-3-ag": {'vulns_epss': {'filterType': 'number', 'type': 'lessThan', 'filter': 20}}}

                elif epss_rank == "< 40":
                    filter_opt = {
                        "query-3-ag": {'vulns_epss': {'filterType': 'number', "operator": "AND",
                                                      "conditions": [
                                                          {"filter": 20, "filterType": "number",
                                                           "type": "greaterThanOrEqual"},
                                                          {"filter": 40, "filterType": "text", "type": "lessThan"}
                                                      ]}}}
                elif epss_rank == "< 60":
                    filter_opt = {
                        "query-3-ag": {'vulns_epss': {'filterType': 'number', "operator": "AND",
                                                      "conditions": [
                                                          {"filter": 40, "filterType": "number",
                                                           "type": "greaterThanOrEqual"},
                                                          {"filter": 60, "filterType": "number", "type": "lessThan"}
                                                      ]}}}
                elif epss_rank == "< 80":
                    filter_opt = {
                        "query-3-ag": {'vulns_epss': {'filterType': 'number', "operator": "AND",
                                                      "conditions": [
                                                          {"filter": 60, "filterType": "number",
                                                           "type": "greaterThanOrEqual"},
                                                          {"filter": 80, "filterType": "number", "type": "lessThan"}
                                                      ]}}}
                else:
                    filter_opt = {
                        "query-3-ag": {
                            'vulns_epss': {'filterType': 'number', 'type': 'greaterThanOrEqual', 'filter': 80}}}



                return "/dashboard/cve", filter_opt
        return no_update, no_update
