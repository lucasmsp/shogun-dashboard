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


def register_layout_query(filter_modal={}):
    columns, raw_data = gen_columns_def(['ip', 'org_clean', 'vulns_cve_id',
                                         'vulns_cvss', 'vulns_epss', "cpe_product"])

    # columns['ip']["maxNumConditions"] = 500
    columns['ip']["tooltipValueGetter"] = {"function": "'Click on the cell for more details'"}
    columns['ip']['pinned'] = 'left'
    columns['vulns_epss']["tooltipField"] = "vulns_epss_rank"
    columns['vulns_cvss']["tooltipField"] = "vulns_cvss_version"

    aggrid = dag.AgGrid(
        id="query-2a-grid",
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
                    width=9,
                    style={"textAlign": "left", "paddingLeft": "15px"}
                ),
                dbc.Col(
                    dbc.Button(
                        [html.I(className="fas fa-download me-2"), "Export to CSV"],
                        id="btn-export-query2-ips",
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

    @app.callback(
        Output('query-2a-grid', "getRowsResponse"),
        [
            Input('date-picker-single', 'value'),
            Input("query-2a-grid", "getRowsRequest"),
        ]
    )
    def update_grid2a(date_value, request):

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        df = df[['ip', 'org_clean', 'vulns_cve_id', 'vulns_cvss', 'vulns_epss',
                 "cpe_product", "vulns_epss_rank", "vulns_cvss_version"]]
        lines = len(df.index)
        logging.info(f"original dataset ({date_value}) has {lines} lines")
        if request is None:
            raise PreventUpdate
       
        if request["filterModel"]:
            filters = request["filterModel"]
            for col, filter_conf in filters.items():
                try:
                    df = filter_by_model(filter_conf, df, col)
                    lines = len(df.index)
                except:
                    logging.error("error filter grid2a")

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

        if filter_modal:
            df = filter_text(filter_modal, df, "org_clean")
            df = filter_text(filter_modal, df, "ip")
            df = filter_number(filter_modal, df, "vulns_epss")
            df = filter_text(filter_modal, df, "vulns_cvss_rank")
            df = filter_text(filter_modal, df, "cpe_product")

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
                return "/dashboard/report", filter_opt
        raise PreventUpdate


    @app.callback(
        Output("query-2a-grid", "exportDataAsCsv"),
        Input("btn-export-query2-ips", "n_clicks"),
        prevent_initial_call=True
    )
    def export_csv_query2_ips(n_clicks):
        if n_clicks:
            return True
        return False
