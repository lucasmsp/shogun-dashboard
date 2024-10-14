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


INPUT_DATA_V2 = '2'

def register_layout_query(filter_modal={}):

    elements = [
        html.H2(children="List of vulnerable products for each IP", className='wrapper'),
        html.H2(
            children="This visualization allows for assessing the higher vulnerability of an IP based on the EPSS score. Users can click on IP to further analysis.",
            style={'fontSize': '20px', 'padding': 10, }
        ),

        dbc.Row(
            dcc.Loading([
                dag.AgGrid(
                    id="query-2a-grid",
                    rowData=[{"org_clean": "Processing...", "ip": "-", "score": 0, "cvss_rank": "-", "cvss_score": "0",
                              "cpe_product": "-", "cve_id": ""}],
                    columnDefs=[
                        {"field": 'org_clean', "headerName": 'Organization (clean)',
                         "filterParams": {"filterOptions": ["equals", "notEqual", 'contains']}},
                        {"field": 'ip', "headerName": 'IP',
                         "tooltipValueGetter": {"function": "'Click on the cell for more details'"},
                         "filterParams": {"filterOptions": ["equals", "notEqual", 'contains']}
                         },
                        {"field": 'epss', "headerName": 'EPSS', "tooltipField": "epss_rank",
                         "filter": "agNumberColumnFilter", "filterParams": {
                            "filterOptions": ["equals", "notEqual", 'lessThan', 'greaterThan', 'inRange']}},
                        {"field": 'cvss_rank', "headerName": 'CVSS Rank', "tooltipField": "cvss_score",
                         "filterParams": {"filterOptions": ["equals", "notEqual", 'contains']}},
                        {
                            "field": 'cpe_product',
                            "headerName": 'Product name',
                            "filterParams": {"filterOptions": ["equals", "notEqual", 'contains']}
                        },
                        {"field": 'cve_id', "headerName": 'CVE',
                         "filterParams": {"filterOptions": ["equals", "notEqual", 'contains']}
                         },
                    ],
                    defaultColDef={"flex": 1, "filter": True},
                    columnSize="sizeToFit",
                    filterModel=filter_modal,
                    columnSizeOptions={"skipHeader": False},
                    dashGridOptions={
                        'tooltipInteraction': True,
                        'tooltipShowDelay': 10,
                        'tooltipHideDelay': 10000
                    }
                )
            ])
        ),

        html.Br(),
        dbc.Row(
            [
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-color-2a",
                        options=[
                            "Scatter plot - EPSS by CVSS score",
                            "Bar plot - Number of CVE by CVSS Rank",
                            "PDF/CDF plot - EPSS Distribution",
                            "Bar plot - Top 10 vulnerable products"

                        ],
                        clearable=False,
                        style={
                            "width": "90%",
                            "margin": "15px",
                        },
                        value='Scatter plot - EPSS by CVSS score'
                    ),
                )

            ]
        ),
        dcc.Graph(
            id="query-2a-graph",
            config={
                'displayModeBar': False,
                'scrollZoom': False
            },
            style={
                "display": "flex",
            }
        )
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
        Output('query-2a-grid', "rowData"),
        [
            Input('date-picker-single', 'value'),
        ]
    )
    def update_grid2a(date_value):

        print("[INFO] query 2 - update_table2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)

        if df.empty:
            return [{}]
        
        return df.to_dict('records')


    def gen_graphs(df, metric):
        fig = go.Figure()
        if metric == "PDF/CDF plot - EPSS Distribution":
            stats_df = df \
                .groupby('epss') \
                ['epss'] \
                .agg('count') \
                .pipe(pd.DataFrame) \
                .rename(columns = {'epss': 'frequency'})

            # PDF
            stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])

            # CDF
            stats_df['cdf'] = stats_df['pdf'].cumsum()
            stats_df = stats_df.reset_index()

            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['pdf'], mode='lines', name='PDF'))
            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['cdf'], mode='lines', name='CDF'))
            fig.update_layout(title='PDF and CDF of EPSS Score',
                            xaxis_title='EPSS',
                            yaxis_title='Probability',
                            showlegend=True)
        
        elif metric == "Bar plot - Number of CVE by CVSS Rank":      
            
            severity_mapping = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4
            }
            df['severity'] = df['cvss_rank'].map(severity_mapping)

            cvss_counts = df.groupby(['cvss_rank', 'severity'])['cvss_rank'].count().reset_index(name='total_count')
            cvss_counts = cvss_counts.sort_values(by=['severity'], ascending=True)

            fig.add_trace(go.Bar(x=cvss_counts.cvss_rank, y=cvss_counts.total_count, name='CVSS Rank'))

            fig.update_layout(
                # title='Distribution of CVSS Rank',
                xaxis=dict(title='CVSS Rank'),
                yaxis=dict(title='Number of IPs'))

        elif metric == "Scatter plot - EPSS by CVSS score": 

            fig = px.scatter(df, 
                             x=df["cvss_score"],
                             y=df['epss'], 
                             title="Scatter plot - EPSS by CVSS score",
                             color='epss_rank')
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="EPSS Score",
                # xaxis=dict(showticklabels=False),
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )

        elif metric == "Bar plot - Top 10 vulnerable products":
            number_ips = df['ip'].nunique()
            top_products = df.groupby(['cpe_product'])['cvss_rank'].count().reset_index(name='total_count')
            if len(top_products) > 10:
                top_products = top_products[:10]
            top_products['percent'] = 100 * (top_products.total_count / number_ips)
            top_products = top_products.sort_values(by=['total_count'], ascending=False)
            
            fig.add_trace(go.Bar(x=top_products.cpe_product, 
                                 y=top_products.percent,
                                 name='Top 10 products'))

            fig.update_layout(
                xaxis=dict(title='Product'),
                yaxis=dict(title='Percentage of IPs')
                )

        return fig

    @app.callback(
        Output('query-2a-graph', 'figure'),
        [
            Input('date-picker-single', 'value'),
            Input('query-2a-grid', 'filterModel'),
            Input("dropdown-color-2a", 'value'),
        ]
    )
    def update_graph2a(date_value, filter_modal, metric):

        print("[INFO] query 2 - update_graph2a: ")

        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return {}
        
        df = filter_text(filter_modal, df, "org_clean")
        df = filter_text(filter_modal, df, "ip")
        df = filter_number(filter_modal, df, "epss")
        df = filter_text(filter_modal, df, "cvss_rank")
        df = filter_text(filter_modal, df, "cpe_product")

        fig = gen_graphs(df, metric)
        return fig


    @app.callback(
        Output('query-5-ag', 'filterModel'),
        Output("query-2a-grid", "cellClicked"),
        Input("query-2a-grid", "cellClicked"),
    )
    def select_ip(cell):

        filter_opt = {}
        if cell:
            if cell.get("colId", "") == "ip_str":
                value = cell.get('value', "")
                filter_opt = {'ip': {'filterType': 'text', 'type': 'equals', 'filter': value}}

                return filter_opt, {}
        return filter_opt, {}
    

    # @app.callback(
    #     Output('v2-content', 'children'),
    #     Input("url-redirect", "pathname"),
    # )
    # def tab_v2_select(pathname):
    #     if pathname == "/dashboard/v2a":
    #         return tab1_content
    #     elif pathname == "/dashboard/v2b":
    #         return tab2_content


