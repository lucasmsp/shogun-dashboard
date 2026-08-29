from dash import html, dcc, Output, Input, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

import plotly.express as px
import plotly.graph_objs as go
import dash_ag_grid as dag

from project.auxiliar import gen_subgraphs, gen_columns_def, logging

INPUT_DATA = 'summary'

def register_layout_query(filter_modal={}):
    """
    Register the layout for the first query (EPSS summary).

    Args:
        filter_modal (dict): Filter modal configuration.

    Returns:
        dbc.Card: Layout for the first query.
    """

    columns, raw_data = gen_columns_def(['vulns_epss_rank', 'n_cves', 'n_ips', 'n_orgs', 'n_as'])
    columns['n_cves']["tooltipValueGetter"] = {"function": "'Click on the cell for more details'"}

    aggrid = dag.AgGrid(
        id='query-1-table',
        columnDefs=list(columns.values()),
        rowData=raw_data,
        defaultColDef={"flex": 1, "resizable": False, "filter": True},
        columnSize="responsiveSizeToFit",
        columnSizeOptions={"skipHeader": False},
        dashGridOptions={"rowSelection": "single", "animateRows": False},
        csvExportParams={
            "fileName": "query1_epss_summary.csv",
            "exportedRows": "filteredAndSorted",
        },
        style={"height": 260}
    )

    elements = [
        html.H1(children="View 1 - EPSS summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
              dbc.Row(aggrid),
              dbc.Row(
                  [
                      dbc.Col(
                          html.Small(
                              [
                                  html.I(className="fas fa-info-circle me-1", style={"color": "#17a2b8"}),
                                  " Tip: Click on any cell under the ",
                                  html.Strong("# CVEs"),
                                  " column to redirect and view detailed CVE information filtered by that EPSS rank."
                              ],
                              className="text-muted mt-2"
                          ),
                          width=9,
                          style={"textAlign": "left", "paddingLeft": "15px"}
                      ),
                      dbc.Col(
                          dbc.Button(
                              [html.I(className="fas fa-download me-2"), "Export to CSV"],
                              id="btn-export-query1",
                              color="primary",
                              size="sm",
                              className="mt-2",
                              style={"float": "right"}
                          ),
                          width=3
                      )
                  ],
                  justify="between",
                  align="center"
              ),
              dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
              dbc.Row(dcc.Loading([html.Div(id='query-1-graph', children=[])]))
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
    """
    Register the callbacks for the first query (EPSS summary).

    Args:
        dm (DataManager): Data manager instance.
        app (dash.Dash): Dash application instance.
    """

    @app.callback(
        Output('query-1-table', "rowData"),
        Input('date-picker-single', 'value')
    )
    def update_table1(date_value):
        if not date_value:
            return []

        logging.info(f"update_table1: {date_value}")
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        return df.to_dict('records')


    @app.callback(
        Output('query-1-table', "exportDataAsCsv"),
        Input('btn-export-query1', 'n_clicks'),
        prevent_initial_call=True
    )
    def export_csv_query1(n_clicks):
        if n_clicks:
            return True
        return False


    @app.callback(
        Output("query-1-graph", "children"),
        Input('date-picker-single', 'value')
    )
    def update_chart1(date_value):
        if not date_value:
            return []

        logging.info(f"update_chart1: {date_value}")
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
        Output('dummy-redirect-q1', 'children', allow_duplicate=True),
        
        State("url-redirect", "pathname"),
        Input("query-1-table", "cellClicked"),
        State("query-1-table", "selectedRows"),
        State("query-1-table", "rowData"),
        State('date-picker-single', 'value'),
        prevent_initial_call=True,
    )
    def go_to_queries(pathname, cell, row, row_data, date_value):
        if cell and pathname == "/dashboard/summary":
            if cell.get("colId", "") == "n_cves":
                logging.info(f"Clicked cell {cell} and row {row}")
                epss_rank = None
                if isinstance(cell.get("data"), dict):
                    epss_rank = cell["data"].get("vulns_epss_rank")

                if not epss_rank and row and isinstance(row, list) and len(row) > 0 and isinstance(row[0], dict):
                    epss_rank = row[0].get("vulns_epss_rank")

                if not epss_rank and row_data and isinstance(row_data, list):
                    try:
                        row_idx = int(cell.get("rowIndex", cell.get("rowId", 0)))
                        if 0 <= row_idx < len(row_data):
                            epss_rank = row_data[row_idx].get("vulns_epss_rank")
                    except (ValueError, TypeError):
                        pass

                if not epss_rank and date_value:
                    try:
                        df = dm.get_view_dataset(date_value, INPUT_DATA)
                        row_idx = int(cell.get("rowId", cell.get("rowIndex", 0)))
                        if not df.empty and row_idx in df.index:
                            epss_rank = df.at[row_idx, "vulns_epss_rank"]
                    except Exception:
                        pass

                if not epss_rank:
                    raise PreventUpdate

                if epss_rank == "< 20":
                    filter_opt = {
                        "query-3-ag": {'vulns_epss': {'filterType': 'number', 'type': 'lessThan', 'filter': 20}}}

                elif epss_rank == "< 40":
                    filter_opt = {
                        "query-3-ag": {'vulns_epss': {'filterType': 'number', "operator": "AND",
                                                      "conditions": [
                                                          {"filter": 20, "filterType": "number",
                                                           "type": "greaterThanOrEqual"},
                                                          {"filter": 40, "filterType": "number", "type": "lessThan"}
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

                return "/dashboard/cve", filter_opt, ""
        raise PreventUpdate
