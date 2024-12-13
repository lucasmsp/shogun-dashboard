from dash import html, dcc, dash_table, callback_context, ctx, no_update
from dash.dependencies import Output, Input, State
import dash_bootstrap_components as dbc
import dash_ag_grid as dag

import itertools
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import re
from project.filters import *

from project.auxiliar import gen_subgraphs, gen_columns_def

INPUT_DATA_V2 = '2'

def register_layout_query(filter_modal={}):
    columns, raw_data = gen_columns_def(['org_clean', 'ip', 'vulns_cve_id', 'vulns_cvss_score',
                               'vulns_epss', "cpe_product"])

    columns[1]["tooltipValueGetter"]= {"function": "'Click on the cell for more details'"}
    columns[4]["tooltipField"] = "vulns_epss_rank"

    aggrid = dag.AgGrid(
        id="query-2a-grid",
        rowData=raw_data,
        columnDefs=columns,
        defaultColDef={"flex": 1, "filter": True},
        columnSize="sizeToFit",
        filterModel=filter_modal,
        columnSizeOptions={"skipHeader": False},
        dashGridOptions={
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
        getRowId="params.data.index"
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

        print("[INFO] query 2 - update_table2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        print(f"[INFO] query 2 - original dataset has {len(df)} lines")

        if request:
            if request["filterModel"]:
                filters = request["filterModel"]
                for col, filter_conf in filters.items():
                    try:
                        df = filter_by_model(filter_conf, df, col)
                    except:
                        print("[ERROR] query 2 - error filter grid2a")

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

            lines = len(df.index)
            if lines == 0:
                lines = 1

            partial = df.iloc[request["startRow"]: request["endRow"]]

            return {"rowData": partial.to_dict("records"), "rowCount": lines}

    @app.callback(
        Output('query-2a-graph', 'children'),
        [
            Input('date-picker-single', 'value'),
            Input('query-2a-grid', 'filterModel')
        ]
    )
    def update_graph2a(date_value, filter_modal):

        print("[INFO] query 2 - update_graph2a.")

        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
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
                          xaxis_title='EPSS',
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
        fig = px.scatter(df,
                         x=df["vulns_cvss_score"],
                         y=df['vulns_epss'],
                         title="Scatter plot - EPSS by CVSS score",
                         color='vulns_epss_rank')
        fig.update_layout(
            title="Scatter plot - EPSS by CVSS score",
            xaxis_title="CVSS Score",
            yaxis_title="EPSS Score",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 2, 4, 6, 8, 10],
                range=[0, 10]
            )
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
                filter_opt = {'ip': {'filterType': 'text', 'type': 'equals', 'filter': value}}
                print("[INFO][select_ip] - ", filter_opt)
                return "/dashboard/report", filter_opt
        return no_update, no_update
