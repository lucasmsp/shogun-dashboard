from dash import html, dcc, Output, Input, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import dash_ag_grid as dag

import plotly.express as px
import plotly.graph_objs as go
import pandas as pd

from project.filters import *
from project.auxiliar import gen_subgraphs, gen_columns_def, logging

INPUT_DATA = 'ips'


import ast


def format_cve_tooltip(x):
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return "Total: 0 CVEs"

    # If x is numpy array, list, tuple, set, etc.
    if hasattr(x, '__len__') and not isinstance(x, (str, bytes, dict)):
        try:
            items = [str(item).strip() for item in x if item and str(item).strip() and str(item) != 'nan']
            if items:
                total = len(items)
                top15 = items[:15]
                return f"Total: {total} CVEs | Top 15: {', '.join(top15)}"
        except Exception:
            pass

    # If x is a string
    if isinstance(x, str):
        s = x.strip()
        if not s or s in ['[]', 'None', 'nan']:
            return "Total: 0 CVEs"

        if s.startswith('[') and s.endswith(']'):
            try:
                parsed = ast.literal_eval(s)
                if isinstance(parsed, (list, tuple, set)):
                    items = [str(item).strip() for item in parsed if item and str(item).strip()]
                    if items:
                        total = len(items)
                        top15 = items[:15]
                        return f"Total: {total} CVEs | Top 15: {', '.join(top15)}"
            except Exception:
                pass
            s_clean = s.strip('[]').replace("'", "").replace('"', "")
            items = [item.strip() for item in s_clean.split(',') if item.strip()]
            if items:
                total = len(items)
                top15 = items[:15]
                return f"Total: {total} CVEs | Top 15: {', '.join(top15)}"

        if ',' in s:
            items = [item.strip() for item in s.split(',') if item.strip()]
            if items:
                total = len(items)
                top15 = items[:15]
                return f"Total: {total} CVEs | Top 15: {', '.join(top15)}"

    return "Total: 0 CVEs"


def include_cve_id_in_list(df):
    if 'vulns_cve_id' not in df.columns:
        return df

    target_list_col = 'vulns_cve_list' if 'vulns_cve_list' in df.columns else ('cve_list' if 'cve_list' in df.columns else 'vulns_cve_list')

    if target_list_col not in df.columns:
        df[target_list_col] = df['vulns_cve_id'].apply(lambda x: [str(x)] if pd.notna(x) and str(x).strip() and str(x) != 'nan' else [])
        return df

    def combine(row):
        cve_id = row.get('vulns_cve_id')
        cve_list = row.get(target_list_col)

        res = []
        if isinstance(cve_list, (list, tuple, set)):
            res = list(cve_list)
        elif hasattr(cve_list, 'tolist'):
            res = cve_list.tolist()
        elif isinstance(cve_list, str) and cve_list.startswith('[') and cve_list.endswith(']'):
            try:
                parsed = ast.literal_eval(cve_list)
                res = list(parsed) if isinstance(parsed, (list, tuple, set)) else []
            except Exception:
                res = [item.strip() for item in cve_list.strip('[]').replace("'", "").replace('"', "").split(',') if item.strip()]

        if pd.notna(cve_id) and str(cve_id).strip() and str(cve_id) != 'nan':
            cve_id_str = str(cve_id).strip()
            if cve_id_str not in res:
                res.append(cve_id_str)

        return res

    df[target_list_col] = df.apply(combine, axis=1)
    return df

def register_layout_query(filter_modal={}):
    """
    Register the layout for the second query (list of vulnerable products for each IP).

    Args:
        filter_modal (dict): Filter configuration.

    Returns:
        dbc.Card: Layout for the second query.
    """
    columns, raw_data = gen_columns_def(['ip', 'org_clean', 'vulns_cve_id',
                                         'vulns_cvss', 'vulns_epss', "cpe_product"])

    columns['ip']["tooltipValueGetter"] = {"function": "'Click on the cell for more details'"}
    columns['ip']['pinned'] = 'left'
    columns['vulns_epss']["tooltipField"] = "vulns_epss_rank"
    columns['vulns_cvss']["tooltipField"] = "vulns_cvss_version"
    columns['vulns_cve_id']["tooltipField"] = "cve_list_tooltip"

    aggrid = dag.AgGrid(
        id="query-2a-grid",
        rowData=raw_data,
        columnDefs=list(columns.values()),
        defaultColDef={"flex": 1, "filter": True},
        columnSize="sizeToFit",
        filterModel=filter_modal,
        columnSizeOptions={"skipHeader": False},
        dashGridOptions={
            "rowSelection": "single",
            'animateRows': False,
            "suppressColumnMoveAnimation": True,

            'tooltipInteraction': True,
            'tooltipShowDelay': 10,
            'tooltipHideDelay': 10000,

            # The number of rows rendered outside the viewable area the grid renders.
            "rowBuffer": 0,
            # How many blocks to keep in the store. Default is no limit, so every requested block is kept.
            "maxBlocksInCache": 2,
            "cacheBlockSize": 5000, # complete data has +- 35k records
            "cacheOverflowSize": 2,
            "maxConcurrentDatasourceRequests": 2,
            "infiniteInitialRowCount": 1,
        },
        rowModelType="infinite",
        getRowId="params.data.index",
        csvExportParams={
            "fileName": "query2_ips.csv",
            "exportedRows": "filteredAndSorted",
        }
    )

    elements = [
        dbc.Row(
            html.Div([
                html.H2(children="List of vulnerable products for each IP", className='wrapper'),
                html.H2(
                    children="This visualization allows for assessing the higher vulnerability of an IP"
                             " based on the EPSS score. Users can click on IP to further analysis.",
                    style={'fontSize': '20px', 'padding': 10, }
                )
            ])
        ),
        dcc.Loading([aggrid]),
        dbc.Row(
            [
                dbc.Col(
                    html.Small(
                        [
                            html.I(className="fas fa-info-circle me-1", style={"color": "#17a2b8"}),
                            " Tip: Click on any IP address under the ",
                            html.Strong("IP"),
                            " column to redirect to the General analysis per record view, filtered by that IP."
                        ],
                        className="text-muted mt-2"
                    ),
                    width=7,
                    style={"textAlign": "left", "paddingLeft": "15px"}
                ),
                dbc.Col(
                    html.Div(
                        [
                            html.Span(
                                id="query-2a-row-count",
                                className="me-3 text-muted align-middle",
                                style={"fontSize": "14px", "fontWeight": "500"}
                            ),
                            dbc.Button(
                                [html.I(className="fas fa-download me-2"), "Export to CSV"],
                                id="btn-export-query2-ips",
                                color="primary",
                                size="sm",
                            )
                        ],
                        className="d-flex align-items-center justify-content-end mt-2"
                    ),
                    width=5
                )
            ],
            justify="between",
            align="center"
        ),
        dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
        dbc.Row([html.Div(id='query-2a-graph', children=[])]),
    ]

    tab2_content_ips = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=elements)], className="wrapper"),
        ),
        className="mt-3",
        id="tab2_content_ips"
    )

    return tab2_content_ips




def register_callback_query(dm, app):
    """
    Register the callbacks for the second query (list of vulnerable products for each IP).

    Args:
        dm (DataManager): Data manager instance.
        app (dash.Dash): Dash application instance.
    """

    @app.callback(
        Output('query-2a-grid', "getRowsResponse"),
        [
            Input('date-picker-single', 'value'),
            Input("query-2a-grid", "getRowsRequest"),
        ]
    )
    def update_grid2a(date_value, request):

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        cols_to_keep = ['ip', 'org_clean', 'vulns_cve_id', 'vulns_cvss', 'vulns_epss',
                        "cpe_product", "vulns_epss_rank", "vulns_cvss_version"]
        for possible_cve_col in ['vulns_cve_list', 'cve_list']:
            if possible_cve_col in df.columns and possible_cve_col not in cols_to_keep:
                cols_to_keep.append(possible_cve_col)
        df = df[[c for c in cols_to_keep if c in df.columns]]
        lines = len(df.index)
        logging.info(f"original dataset ({date_value}) has {lines} lines")
        if request is None:
            raise PreventUpdate
       
        df = include_cve_id_in_list(df)
        cve_list_col = 'vulns_cve_list' if 'vulns_cve_list' in df.columns else ('cve_list' if 'cve_list' in df.columns else None)

        if request["filterModel"]:
            filters = request["filterModel"]
            for col, filter_conf in filters.items():
                try:
                    target_col = cve_list_col if col == "vulns_cve_id" and cve_list_col else col
                    df = filter_by_model(filter_conf, df, target_col)
                    lines = len(df.index)
                except Exception as e:
                    logging.error(f"error filter grid2a: {e}")

        if cve_list_col:
            df['cve_list_tooltip'] = df[cve_list_col].apply(format_cve_tooltip)
        elif 'vulns_cve_id' in df.columns:
            df['cve_list_tooltip'] = df['vulns_cve_id'].apply(format_cve_tooltip)
        else:
            df['cve_list_tooltip'] = "Total: 0 CVEs"

        df = df[['ip', 'org_clean', 'vulns_cve_id', 'vulns_cvss', 'vulns_epss',
                 "cpe_product", "vulns_epss_rank", "vulns_cvss_version", "cve_list_tooltip"]]
        if request["sortModel"]:
            sorting = []
            asc = []
            for sort in request["sortModel"]:
                sorting.append(sort["colId"])
                if sort["sort"] == "asc":
                    asc.append(True)
                else:
                    asc.append(False)
            df = df.sort_values(by=sorting, ascending=asc)

        start_row = request["startRow"]
        end_row = request["endRow"]

        partial = df.iloc[start_row:end_row]

        if lines == 0:
            lines = 1

        return {"rowData": partial.to_dict("records"), "rowCount": lines}

    @app.callback(
        Output('query-2a-graph', 'children'),
        [
            Input('date-picker-single', 'value'),
            Input('query-2a-grid', 'filterModel')
        ]
    )
    def update_graph2a(date_value, filter_modal):
        logging.info(date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return {}

        df = include_cve_id_in_list(df)

        if filter_modal:
            for col, filter_conf in filter_modal.items():
                try:
                    target_col = "vulns_cve_list" if col == "vulns_cve_id" and "vulns_cve_list" in df.columns else col
                    df = filter_by_model(filter_conf, df, target_col)
                except Exception as e:
                    logging.error(f"error filter update_graph2a: {e}")

        graphs = []

        # fig1
        stats_df = df \
            .groupby('vulns_epss') \
            ['vulns_epss'] \
            .agg('count') \
            .pipe(pd.DataFrame) \
            .rename(columns={'vulns_epss': 'frequency'})

        stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])
        stats_df['cdf'] = stats_df['pdf'].cumsum()
        stats_df = stats_df.reset_index()

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=stats_df['vulns_epss'], y=stats_df['pdf'], mode='lines', name='PDF'))
        fig.add_trace(go.Scatter(x=stats_df['vulns_epss'], y=stats_df['cdf'], mode='lines', name='CDF'))
        fig.update_layout(title='Line plot - PDF and CDF of EPSS Score Distribution',
                          xaxis_title='EPSS score (%)',
                          yaxis_title='Probability',
                          showlegend=True)
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig2
        fig = go.Figure()
        severity_mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        df['severity'] = df['vulns_cvss_rank'].map(severity_mapping)
        cvss_counts = df.groupby(['vulns_cvss_rank', 'severity'])['vulns_cvss_rank'].count()\
                .reset_index(name='total_count')
        cvss_counts = cvss_counts.sort_values(by=['severity'], ascending=True)
        fig.add_trace(go.Bar(x=cvss_counts.vulns_cvss_rank, y=cvss_counts.total_count, name='CVSS Rank'))
        fig.update_layout(
            title='Bar plot - Number of CVE by CVSS Rank',
            xaxis=dict(title='CVSS Rank'),
            yaxis=dict(title='Number of IPs'))
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig3
        scatter_df = df[['vulns_cvss', 'vulns_epss', 'vulns_epss_rank']].copy()
        scatter_df = scatter_df.dropna()
        scatter_df['vulns_cvss_bin'] = pd.cut(
            pd.to_numeric(scatter_df['vulns_cvss'], errors='coerce').clip(0, 10),
            bins=[i / 2 for i in range(0, 21)],
            labels=[f"{i / 2:.1f}-{(i + 1) / 2:.1f}" for i in range(0, 20)],
            include_lowest=True
        )
        scatter_df = scatter_df.dropna(subset=['vulns_cvss_bin'])
        scatter_df = scatter_df.groupby(['vulns_cvss_bin', 'vulns_epss_rank']).size().reset_index(name='count')

        fig = go.Figure()
        for vulns_cvss_bin in sorted(scatter_df['vulns_cvss_bin'].dropna().unique()):
            subset = scatter_df[scatter_df['vulns_cvss_bin'] == vulns_cvss_bin]
            fig.add_trace(go.Bar(
                x=subset['vulns_cvss_bin'],
                y=subset['count'],
                name=str(vulns_cvss_bin),
                marker=dict(opacity=0.9),
                width=0.35
            ))

        fig.update_layout(
            title="Bar plot - CVSS distribution by EPSS rank",
            xaxis_title="CVSS score",
            yaxis_title="Number of records",
            barmode='group'
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig4
        fig = go.Figure()
        number_ips = df['ip'].nunique()
        top_products = df.groupby(['cpe_product'])['vulns_cvss_rank'].count()\
                .reset_index(name='total_count')
        if len(top_products) > 10:
            top_products = top_products[:10]
        top_products['percent'] = 100 * (top_products.total_count / number_ips)
        top_products = top_products.sort_values(by=['total_count'], ascending=False)

        fig.add_trace(go.Bar(x=top_products.cpe_product,
                             y=top_products.percent,
                             name='Top 10 vulnerable products'))

        fig.update_layout(
            title="Bar plot - Top 10 vulnerable products",
            xaxis=dict(title='Product'),
            yaxis=dict(title='Percentage of IPs')
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        children = gen_subgraphs(n_cols=3, graphs=graphs)
        return children


    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Output('dummy-redirect-q2a', 'children', allow_duplicate=True),
        Input("query-2a-grid", "cellClicked"),
        prevent_initial_call=True
    )
    def select_ip(cell):
        """
        When clicked, go to view2a (IPs), filtering only records in view 5 that belongs
        to the selected organization.
        """

        if cell:
            if cell.get("colId", "") == "ip":
                value = cell.get('value', "")
                filter_opt = {"query-5-ag": {'ip': {'filterType': 'text', 'type': 'equals', 'filter': value}}}
                logging.info(f"{filter_opt}")
                return "/dashboard/report", filter_opt, ""
        raise PreventUpdate


    @app.callback(
        Output("query-2a-grid", "exportDataAsCsv"),
        Input("btn-export-query2-ips", "n_clicks"),
        prevent_initial_call=True
    )
    def export_csv_query2_ips(n_clicks):
        """
        Callback to export the grid data to a CSV file.

        Args:
            n_clicks (int): Number of clicks on the export button.

        Returns:
            bool: True if the export was successful, False otherwise.
        """
        if n_clicks:
            return True
        return False

    @app.callback(
        Output('query-2a-row-count', 'children'),
        [
            Input('date-picker-single', 'value'),
            Input('query-2a-grid', 'filterModel')
        ]
    )
    def update_row_count_2a(date_value, filter_modal):
        """
        Callback to display total and filtered row counts for query 2a.
        """
        if not date_value:
            return ""

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return "0 de 0 registros"

        df = include_cve_id_in_list(df)

        total_rows = len(df.index)

        if filter_modal:
            for col, filter_conf in filter_modal.items():
                try:
                    target_col = "vulns_cve_list" if col == "vulns_cve_id" and "vulns_cve_list" in df.columns else col
                    df = filter_by_model(filter_conf, df, target_col)
                except Exception as e:
                    logging.error(f"error filter row count grid2a: {e}")

        filtered_rows = len(df.index)

        if filter_modal:
            return f"Exibindo {filtered_rows:,} de {total_rows:,} registros".replace(",", ".")
        else:
            return f"Total: {total_rows:,} registros".replace(",", ".")
