from dash import html, dcc, dash_table, callback_context, ctx, no_update
from dash.dependencies import Output, Input, State
import dash_bootstrap_components as dbc
import dash_ag_grid as dag

import itertools
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import re


INPUT_DATA_V2 = '2'
TAB_VIEW = "tab-1"

def register_layout_query(dm):

    tab1_content = [
        html.H2(children="List of vulnerable products for each IP", className='wrapper'),
        html.H2(
            children="This visualization allows for assessing the higher vulnerability of an IP based on the EPSS score. Users can click on IP to further analysis.",
            style={'fontSize': '20px', 'padding': 10,}
        ),

        dbc.Row(
            dag.AgGrid(
                id="query-2a-grid",
                columnDefs=[
                    {"field": 'org_clean', "headerName": 'Organization (clean)', "filterParams": {"filterOptions": ["equals","notEqual",'contains']}},
                    {"field": 'ip_str', "headerName": 'IP',
                      "tooltipValueGetter": {"function": "'Click on the cell for more details'"},
                       "filterParams": {"filterOptions": ["equals","notEqual",'contains']} 
                    },
                    {"field": 'epss', "headerName": 'EPSS', "tooltipField": "epss_rank", 
                     "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}},
                    {"field": 'cvss_rank', "headerName": 'CVSS Rank', "tooltipField": "cvss_score", "filterParams": {"filterOptions": ["equals","notEqual",'contains']}},
                    {
                        "field": 'cpe_product', 
                        "headerName": 'Product name', 
                        "tooltipField": "cve_id",
                        "filterParams": {"filterOptions": ["equals","notEqual",'contains']}
                    },
                ],
                defaultColDef={"flex": 1, "filter": True},
                columnSize="responsiveSizeToFit",
                columnSizeOptions= {"skipHeader": False},
                dashGridOptions={
                    'tooltipInteraction': True,
                    'tooltipShowDelay': 10, 
                    'tooltipHideDelay': 10000
                }
            )
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

    tab2_content = [
        html.H2(children="Highest EPSS for each org", className='wrapper'),
        html.H2(
            children="This visualization allows for assessing the higher vulnerability of an Organization based on the EPSS score. Users can click on an organization to further informations.",
            style={'fontSize': '20px', 'padding': 10,}
        ),

        dbc.Row(
            dag.AgGrid(
                id="query-2b-grid",
                columnDefs=[
                    {"field": 'org_clean', "headerName": 'Organization', "filterParams": {"filterOptions": ["equals","notEqual",'contains']}},
                    {"field": 'epss', "headerName": 'EPSS (major)', 
                     "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}},
                ],
                defaultColDef={"flex": 1, "filter": True},
                columnSize="responsiveSizeToFit",
                columnSizeOptions= {"skipHeader": False},
                dashGridOptions={"rowSelection": "single", "animateRows": False}
            )
        ),

        html.Br(),

        dbc.Row(
            [
                dbc.Col(
                    dcc.Dropdown(
                        id="dropdown-type-2b",
                        clearable=False,
                        options=[
                            "PDF/CDF plot - EPSS Distribution by Organization",
                            'PDF/CDF - Distribution of the number of CVE by Organization',
                            "PDF/CDF - Distribution of the number of vulnerable Products by Organization"
                            
                        ],
                        style={
                            "width": "90%",
                            "margin": "15px",
                        },
                        value="PDF/CDF plot - EPSS Distribution by Organization"
                    ),
                )
            ]
        ),

        dcc.Graph(
            id="query-2b-graph",
            config={
                'displayModeBar': False,
                'scrollZoom': False
            }
        )
    ]


    q2 = [
        html.H1(children="View 2 - by organizations/IP", className='wrapper'),
        html.Br(),
        dbc.Tabs(
            [
                dbc.Tab(tab2_content, label="Highest EPSS for each org"),
                dbc.Tab(tab1_content, label="List of vulnerable products for each IP"),
            ],
            id="query2-tabs",
        )
    ]

    return q2



def filter_text(filter_modal, df, col):

    org_query = filter_modal.get(col, None)
    if org_query:
        
        type_ = org_query.get("type", 'contains')
        value = org_query.get("filter", '')
        if type_ == "contains":
            df = df[df[col].str.contains(value, case=False)]
        elif type_ == "equals":
            df = df[df[col] == value]
        elif type_ == "equals":
            df = df[df[col] != value]
    
    return df

def filter_number(filter_modal, df, col):
    opt =  filter_modal.get(col, None)
    if opt:
        type_ = opt.get("type", 'equals')
        value = opt.get("filter", '')
        if type_ == "equals":
            df = df[df[col] == value]
        elif type_ == "lessThan":
            df = df[df[col] <= value]
        elif type_ == "greaterThan":
            df = df[df[col] >= value]
        elif type_ == "notEqual":
            df = df[df[col] != value]
    return df


def register_callback_query(dm, app):

    @app.callback(
        Output('query-2a-grid', "rowData"),
        [
            Input('date-picker-single', 'value'),
            Input("general-tabs", "active_tab"),
        ], prevent_initial_call=True
    )
    def update_grid2a(date_value, active_tab):
        if TAB_VIEW != active_tab:
            return [{}]
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
            number_ips = df['ip_str'].nunique()
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
            Input('query-2a-grid', "rowData"),
            Input('query-2a-grid', 'filterModel'),
            Input("dropdown-color-2a", 'value'),
            Input("general-tabs", "active_tab"),
        ], prevent_initial_call=True
    )
    def update_graph2a(data_input, filter_modal, metric, active_tab):
        if TAB_VIEW != active_tab:
            return {}
        print("[INFO] query 2 - update_graph2a: ")

        df = pd.DataFrame.from_dict(data_input)
        if df.empty:
            return {}
        
        df = filter_text(filter_modal, df, "org_clean")
        df = filter_text(filter_modal, df, "ip_str")
        df = filter_number(filter_modal, df, "epss")
        df = filter_text(filter_modal, df, "cvss_rank")
        df = filter_text(filter_modal, df, "cpe_product")

        fig = gen_graphs(df, metric)
        return fig
        
    
    @app.callback(
        
        Output("query-2b-grid", "rowData"),
        [
            Input('date-picker-single', 'value'),
            Input("general-tabs", "active_tab"),
        ], prevent_initial_call=True
    )
    def update_grid2b(date_value, active_tab):
        if TAB_VIEW != active_tab:
            return [{}]

        print("[INFO] query 2 - update_table2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return [{}]
        
        aggregated_df = df.groupby('org_clean').agg({
            'ip_str': lambda x: list(x),
            'cve_id': lambda x: list(x),
            'cpe_product': lambda x: list(x),
            'epss': 'max', 
        }).reset_index()

        return aggregated_df.to_dict('records')

    @app.callback(
        Output('query-2b-graph', 'figure'),

        Input("query-2b-grid", "rowData"),
        Input('query-2b-grid', 'filterModel'),
        Input("dropdown-type-2b", 'value'), 
        Input("general-tabs", "active_tab"),
        prevent_initial_call=True
    )
    def update_graph2b(data_input, filter_modal, metric, active_tab):
        if TAB_VIEW != active_tab:
            return {}
        print("[INFO] query 2 - update_graph2b: ")

        aggregated_df = pd.DataFrame.from_dict(data_input)
        if aggregated_df.empty:
            return {}

        aggregated_df["n_ips"] = aggregated_df["ip_str"].apply(len)
        aggregated_df = aggregated_df.sort_values("n_ips")
        
        aggregated_df = filter_text(filter_modal, aggregated_df, "org_clean")
        aggregated_df = filter_number(filter_modal, aggregated_df, "epss")
   
        fig = go.Figure()

        if metric == "PDF/CDF plot - EPSS Distribution by Organization":
            stats_df = aggregated_df \
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
                            xaxis_title='EPSS score (by organization)',
                            yaxis_title='Probability',
                            showlegend=True)

        elif metric == "PDF/CDF - Distribution of the number of CVE by Organization":

            aggregated_df["n_cves"] = aggregated_df["cve_id"].apply(len)
            print(aggregated_df)
            stats_df = aggregated_df \
                .groupby('n_cves') \
                ['n_cves'] \
                .agg('count') \
                .pipe(pd.DataFrame) \
                .rename(columns = {'n_cves': 'frequency'})

            # PDF
            stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])
            # CDF
            stats_df['cdf'] = stats_df['pdf'].cumsum()
            stats_df = stats_df.reset_index()

            fig.add_trace(go.Scatter(x=stats_df['n_cves'], y=stats_df['pdf'], mode='lines', name='PDF'))
            fig.add_trace(go.Scatter(x=stats_df['n_cves'], y=stats_df['cdf'], mode='lines', name='CDF'))

            fig.update_layout(title='PDF/CDF - Distribution of the number of CVE by Organization',
                            xaxis_title='# Distinct CVEs',
                            yaxis_title='Probability',
                            showlegend=True,
                            xaxis_range=[1,100])

        elif metric == "PDF/CDF - Distribution of the number of vulnerable Products by Organization":

            aggregated_df["n_products"] = aggregated_df["cpe_product"].apply(len)
            print(aggregated_df)
            stats_df = aggregated_df \
                .groupby('n_products') \
                ['n_products'] \
                .agg('count') \
                .pipe(pd.DataFrame) \
                .rename(columns = {'n_products': 'frequency'})

            # PDF
            stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])
            # CDF
            stats_df['cdf'] = stats_df['pdf'].cumsum()
            stats_df = stats_df.reset_index()

            fig.add_trace(go.Scatter(x=stats_df['n_products'], y=stats_df['pdf'], mode='lines', name='PDF'))
            fig.add_trace(go.Scatter(x=stats_df['n_products'], y=stats_df['cdf'], mode='lines', name='CDF'))

            fig.update_layout(title='PDF/CDF -  Distribution of the number of vulnerable Products by Organization',
                            xaxis_title='# Distinct Products',
                            yaxis_title='Probability',
                            showlegend=True,
                            xaxis_range=[1,100])
        return fig
        
    @app.callback(
        Output("general-tabs", "active_tab"),
        Output('query-5-ag', 'filterModel'),
        Output("query-2a-grid", "cellClicked"),
        Input("general-tabs", "active_tab"),
        Input("query-2a-grid", "cellClicked"),
        prevent_initial_call=True
    )
    def select_ip(active_tab, cell):

        filter_opt = {}  
        if (TAB_VIEW == active_tab) and cell:
            if cell.get("colId", "") == "ip_str":
                value = cell.get('value', "")
                filter_opt = {'ip_str': {'filterType': 'text', 'type': 'equals', 'filter': value}}

                return "tab-4", filter_opt, {}
        return active_tab, filter_opt, {}
    

    @app.callback(
        Output('query-2a-grid', 'filterModel'),
        Output("query-2b-grid", "cellClicked"),
        Output("query2-tabs", "active_tab"),
        Input("query-2b-grid", "cellClicked"),
        prevent_initial_call=True
    )
    def select_org_records(cell):

        filter_opt = {}  
        if cell:
            if cell.get("colId", "") == "org_clean":
                value = cell.get('value', "")
                filter_opt = {'org_clean': {'filterType': 'text', 'type': 'equals', 'filter': value}}

                return filter_opt, {}, "tab-1"
        return filter_opt, {}, "tab-0"