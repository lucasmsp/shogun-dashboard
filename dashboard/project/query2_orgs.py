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
    columns, raw_data = gen_columns_def(['org_clean', 'vulns_epss'])
    columns[1]['headerName'] += " (major)"

    aggrid = dag.AgGrid(
                    id="query-2b-grid",
                    rowData=raw_data,
                    columnDefs=columns,
                    filterModel=filter_modal,
                    defaultColDef={"flex": 1, "filter": True},
                    columnSize="sizeToFit",
                    columnSizeOptions={"skipHeader": False},
                    dashGridOptions={"rowSelection": "single", "animateRows": False}
                )

    elements = [
        dbc.Row(
            html.Div([
                html.H2(children="Highest EPSS for each org", className='wrapper'),
                html.H2(
                    children="This visualization allows for assessing the higher vulnerability of an Organization based on the EPSS score. Users can click on an organization to further information.",
                    style={'fontSize': '20px', 'padding': 10, }
                )
            ])
        ),
        dcc.Loading([aggrid]),
        dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
        dbc.Row([html.Div(id='query-2b-graph', children=[])])
    ]

    tab2_content_orgs = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=elements)], className="wrapper"),
        ),
        className="mt-3",
        id="tab2_content_orgs"
    )

    return tab2_content_orgs




def register_callback_query(dm, app):
    
    @app.callback(
        
        Output("query-2b-grid", "rowData"),
        [
            Input('date-picker-single', 'value'),
        ]
    )
    def update_grid2b(date_value):

        print("[INFO] query 2 - update_table2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return [{}]
        
        aggregated_df = df.groupby('org_clean').agg({
            'ip': lambda x: list(x),
            'vulns_cve_id': lambda x: list(x),
            'cpe_product': lambda x: list(x),
            'vulns_epss': 'max',
        }).reset_index()

        return aggregated_df.to_dict('records')

    @app.callback(
        Output('query-2b-graph', 'children'),

        Input('date-picker-single', 'value'),
        Input('query-2b-grid', 'filterModel')
    )
    def update_graph2b(date_value, filter_modal):
        print("[INFO] query 2 - update_graph2b.")

        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return {}

        df["n_ips"] = df["ip"].apply(len)
        df = df.sort_values("n_ips")

        if filter_modal:
            df = filter_text(filter_modal, df, "org_clean")
            df = filter_number(filter_modal, df, "vulns_epss")

        graphs = []

        # fig1
        fig = go.Figure()
        stats_df = df.groupby('vulns_epss')['vulns_epss']\
            .agg('count') \
            .pipe(pd.DataFrame) \
            .rename(columns = {'vulns_epss': 'frequency'})

        stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])
        stats_df['cdf'] = stats_df['pdf'].cumsum()
        stats_df = stats_df.reset_index()

        if len(stats_df) > 1000:
            stats_df.at[1000, "pdf"] = stats_df[1000:]['pdf'].sum()
            stats_df.at[1000, "cdf"] = stats_df[1000:]['cdf'].sum()
            stats_df = stats_df[:1001]


        fig.add_trace(go.Scatter(x=stats_df['vulns_epss'], y=stats_df['pdf'], mode='lines', name='PDF'))
        fig.add_trace(go.Scatter(x=stats_df['vulns_epss'], y=stats_df['cdf'], mode='lines', name='CDF'))
        fig.update_layout(title='PDF/CDF plot - EPSS Distribution by Organization',
                        xaxis_title='EPSS score (by organization)',
                        yaxis_title='Probability',
                        showlegend=True)

        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig2
        fig = go.Figure()
        df["n_cves"] = df["vulns_cve_id"].apply(len)

        stats_df = df \
            .groupby('n_cves') \
            ['n_cves'] \
            .agg('count') \
            .pipe(pd.DataFrame) \
            .rename(columns = {'n_cves': 'frequency'})

        stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])
        stats_df['cdf'] = stats_df['pdf'].cumsum()
        stats_df = stats_df.reset_index()

        if len(stats_df) > 1000:
            stats_df.at[1000, "pdf"] = stats_df[1000:]['pdf'].sum()
            stats_df.at[1000, "cdf"] = stats_df[1000:]['cdf'].sum()
            stats_df = stats_df[:1001]

        fig.add_trace(go.Scatter(x=stats_df['n_cves'], y=stats_df['pdf'], mode='lines', name='PDF'))
        fig.add_trace(go.Scatter(x=stats_df['n_cves'], y=stats_df['cdf'], mode='lines', name='CDF'))

        fig.update_layout(title='PDF/CDF - Distribution of the number of CVE by Organization',
                        xaxis_title='# Distinct CVEs',
                        yaxis_title='Probability',
                        showlegend=True,
                        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig2
        fig = go.Figure()
        df["n_products"] = df["cpe_product"].apply(len)

        stats_df = df.groupby('n_products')['n_products'] \
            .agg('count') \
            .pipe(pd.DataFrame) \
            .rename(columns = {'n_products': 'frequency'})

        stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])
        stats_df['cdf'] = stats_df['pdf'].cumsum()
        stats_df = stats_df.reset_index()

        fig.add_trace(go.Scatter(x=stats_df['n_products'], y=stats_df['pdf'], mode='lines', name='PDF'))
        fig.add_trace(go.Scatter(x=stats_df['n_products'], y=stats_df['cdf'], mode='lines', name='CDF'))

        fig.update_layout(title='PDF/CDF -  Distribution of the number of vulnerable Products by Organization',
                        xaxis_title='# Distinct Products',
                        yaxis_title='Probability',
                        showlegend=True,
                        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        children = gen_subgraphs(n_cols=3, graphs=graphs)
        return children
        


    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-2b-grid", "cellClicked"),
        prevent_initial_call=True
    )
    def select_org_records(cell):
        """
        When clicked, go to view2b (Orgs), filtering only IP records in view2a (IPs)
        that belongs to the selected organization.
        """
        if cell:
            if cell.get("colId", "") == "org_clean":
                value = cell.get('value', "")
                filter_opt = {"query-2a-grid": {'org_clean': {'filterType': 'text', 'type': 'equals', 'filter': value}}}
                return "/dashboard/view2a", filter_opt
        return no_update, no_update
