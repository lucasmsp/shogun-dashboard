from dash import html, dcc, Output, Input, State, no_update
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import dash_ag_grid as dag

import plotly.express as px
import plotly.graph_objs as go
import pandas as pd

from project.filters import *
from project.auxiliar import gen_subgraphs, gen_columns_def, logging


INPUT_DATA_V2 = 'orgs'

def register_layout_query(filter_modal={}):

    columns, raw_data = gen_columns_def(['org_clean', 'n_ips', 'n_vulns', 'n_products',
                                         'vulns_cve_id', 'vulns_epss', 'vulns_cvss', 'cpe_product' ])  # Group Fields

    columns['vulns_cvss']["tooltipField"] = "vulns_cvss_version"
    columns['org_clean']["maxNumConditions"] = 500
    columns['org_clean']['pinned'] = 'left'

    aggrid = dag.AgGrid(
                    id="query-2b-grid",
                    rowData=raw_data,
                    columnDefs=list(columns.values()),
                    filterModel=filter_modal,
                    defaultColDef={"flex": 1, "filter": True},
                    columnSize="sizeToFit",
                    columnSizeOptions={"skipHeader": False},
                    dashGridOptions={
                        "rowSelection": "single",
                        'tooltipShowDelay': 0,
                        'tooltipHideDelay': 50000,
                        "animateRows": False
                    }
                )

    elements = [
        dbc.Row(
            html.Div([
                html.H2(children="Highest EPSS for each org", className='wrapper'),
                html.H2(
                    children="This visualization allows for assessing the higher vulnerability of an Organization"
                             " based on the EPSS score. Users can click on an organization to further information.",
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
        Input('date-picker-single', 'value')
    )
    def update_grid2b(date_value):
        logging.info(date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            raise PreventUpdate

        return df.to_dict('records')

    @app.callback(
        Output('query-2b-graph', 'children'),

        Input('date-picker-single', 'value'),
        Input('query-2b-grid', 'filterModel')
    )
    def update_graph2b(date_value, filter_modal):
        logging.info(date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            raise PreventUpdate

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
                        xaxis_title='EPSS score (%)',
                        yaxis_title='Probability',
                        showlegend=True)

        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig2
        fig = go.Figure()

        stats_df = df \
            .groupby('n_vulns') \
            ['n_vulns'] \
            .agg('count') \
            .pipe(pd.DataFrame) \
            .rename(columns = {'n_vulns': 'frequency'})

        stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])
        stats_df['cdf'] = stats_df['pdf'].cumsum()
        stats_df = stats_df.reset_index()

        if len(stats_df) > 1000:
            stats_df.at[1000, "pdf"] = stats_df[1000:]['pdf'].sum()
            stats_df.at[1000, "cdf"] = stats_df[1000:]['cdf'].sum()
            stats_df = stats_df[:1001]

        fig.add_trace(go.Scatter(x=stats_df['n_vulns'], y=stats_df['pdf'], mode='lines', name='PDF'))
        fig.add_trace(go.Scatter(x=stats_df['n_vulns'], y=stats_df['cdf'], mode='lines', name='CDF'))

        fig.update_layout(title='PDF/CDF - Distribution of the number of CVE by Organization',
                        xaxis_title='# Distinct CVEs',
                        yaxis_title='Probability',
                        showlegend=True,
                        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig2
        fig = go.Figure()

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
        Output("query-2b-grid", "cellClicked"),

        State("url-redirect", "pathname"),
        Input("query-2b-grid", "cellClicked"),
        prevent_initial_call=True
    )
    def select_org_records(pathname, cell):
        """
        When clicked, go to view2b (Orgs), filtering only IP records in view2a (IPs)
        that belongs to the selected organization.
        """
        if cell and pathname == "/dashboard/orgs":
            if cell.get("colId", "") == "org_clean":
                value = cell.get('value', "")
                filter_opt = {"query-2a-grid": {'org_clean': {'filterType': 'text', 'type': 'equals', 'filter': value}}}
                return "/dashboard/ips", filter_opt, {}
        raise PreventUpdate
