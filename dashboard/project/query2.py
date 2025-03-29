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
    
    q2 = [
        html.H1(children="View 2 - by organizations/IP", className='wrapper'),
        html.Br(),
        dbc.Row(
            [
                html.Div(id="v2-content", className="content")
            ]
        ),
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

    tab1_content = [
        html.H2(children="List of vulnerable products for each IP", className='wrapper'),
        html.H2(
            children="This visualization allows for assessing the higher vulnerability of an IP based on the EPSS score. Users can click on IP to further analysis.",
            style={'fontSize': '20px', 'padding': 10,}
        ),

        dbc.Row(
            dcc.Loading([
                dag.AgGrid(
                    id="query-2a-grid",
                    # rowData = [{"org_clean": "Processing...", "ip_str": "-", "score": 0, "cvss_rank": "-", "cvss_score": "0", "cpe_product": "-", "cve_id": ""}],
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
                    columnSize="sizeToFit",
                    columnSizeOptions= {"skipHeader": False},
                    dashGridOptions={
                        'tooltipInteraction': True,
                        'tooltipShowDelay': 10, 
                        'tooltipHideDelay': 1000,
                        # The number of rows rendered outside the viewable area the grid renders.
                        "rowBuffer": 0,
                        # How many blocks to keep in the store. Default is no limit, so every requested block is kept.
                        "maxBlocksInCache": 2,
                        "cacheBlockSize": 10000,
                        "cacheOverflowSize": 2,
                        "maxConcurrentDatasourceRequests": 2,
                        "infiniteInitialRowCount": 1,
                        "rowSelection": "multiple",
                    },
                    rowModelType="infinite",
                    getRowId="params.data.index"
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

    tab2_content = [
        html.H2(children="Highest EPSS for each org", className='wrapper'),
        html.H2(
            children="This visualization allows for assessing the higher vulnerability of an Organization based on the EPSS score. Users can click on an organization to further informations.",
            style={'fontSize': '20px', 'padding': 10,}
        ),

        dbc.Row(
            dcc.Loading([
                dag.AgGrid(
                    id="query-2b-grid",
                    rowData = [{"org_clean": "Processing...", "epss": "-"}],
                    columnDefs=[
                        {"field": 'org_clean', "headerName": 'Organization', "filterParams": {"filterOptions": ["equals","notEqual",'contains']}},
                        {"field": 'epss', "headerName": 'EPSS (major)', 
                        "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}},
                    ],
                    defaultColDef={"flex": 1, "filter": True},
                    columnSize="sizeToFit",
                    columnSizeOptions= {"skipHeader": False},
                    dashGridOptions={
                        "rowSelection": "single",
                        "animateRows": False,
                        'tooltipInteraction': True,
                        'tooltipShowDelay': 10, 
                        'tooltipHideDelay': 1000,
                        # The number of rows rendered outside the viewable area the grid renders.
                        "rowBuffer": 0,
                        # How many blocks to keep in the store. Default is no limit, so every requested block is kept.
                        "maxBlocksInCache": 2,
                        "cacheBlockSize": 10000,
                        "cacheOverflowSize": 2,
                        "maxConcurrentDatasourceRequests": 2,
                        "infiniteInitialRowCount": 1,
                        "rowSelection": "multiple",
                    },
                    rowModelType="infinite",
                    getRowId="params.data.index"
                )
            ])
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
    
    operators = {
        "greaterThanOrEqual": "ge",
        "lessThanOrEqual": "le",
        "lessThan": "lt",
        "greaterThan": "gt",
        "notEqual": "ne",
        "equals": "eq",
    }

    def filter_df(dff, filter_model, col):
        if "filter" in filter_model:
            if filter_model["filterType"] == "date":
                crit1 = filter_model["dateFrom"]
                crit1 = pd.Series(crit1).astype(dff[col].dtype)[0]
                if "dateTo" in filter_model:
                    crit2 = filter_model["dateTo"]
                    crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
            else:
                crit1 = filter_model["filter"]
                crit1 = pd.Series(crit1).astype(dff[col].dtype)[0]
                if "filterTo" in filter_model:
                    crit2 = filter_model["filterTo"]
                    crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
        if "type" in filter_model:
            if filter_model["type"] == "contains":
                dff = dff.loc[dff[col].str.contains(crit1)]
            elif filter_model["type"] == "notContains":
                dff = dff.loc[~dff[col].str.contains(crit1)]
            elif filter_model["type"] == "startsWith":
                dff = dff.loc[dff[col].str.startswith(crit1)]
            elif filter_model["type"] == "notStartsWith":
                dff = dff.loc[~dff[col].str.startswith(crit1)]
            elif filter_model["type"] == "endsWith":
                dff = dff.loc[dff[col].str.endswith(crit1)]
            elif filter_model["type"] == "notEndsWith":
                dff = dff.loc[~dff[col].str.endswith(crit1)]
            elif filter_model["type"] == "inRange":
                if filter_model["filterType"] == "date":
                    dff = dff.loc[
                        dff[col].astype("datetime64[ns]").between_time(crit1, crit2)
                    ]
                else:
                    dff = dff.loc[dff[col].between(crit1, crit2)]
            elif filter_model["type"] == "blank":
                dff = dff.loc[dff[col].isnull()]
            elif filter_model["type"] == "notBlank":
                dff = dff.loc[~dff[col].isnull()]
            else:
                dff = dff.loc[getattr(dff[col], operators[filter_model["type"]])(crit1)]
        elif filter_model["filterType"] == "set":
            dff = dff.loc[dff[col].astype("string").isin(filter_model["values"])]
        return dff


    @app.callback(
        Output('query-2a-grid', "getRowsResponse"),
        [
            Input('date-picker-single', 'value'),
            Input("query-2a-grid", "getRowsRequest"),
        ],         
    )
    def update_grid2a(date_value, request):

        # print("[INFO] query 2 - update_table2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        dff = df.copy()

        # if df.empty:
        #     return [{}]
        
        # return df.to_dict('records')
        if request:
            if request["filterModel"]:
                filters = request["filterModel"]
                for f in filters:
                    try:
                        if "operator" in filters[f]:
                            if filters[f]["operator"] == "AND":
                                dff = filter_df(dff, filters[f]["condition1"], f)
                                dff = filter_df(dff, filters[f]["condition2"], f)
                            else:
                                dff1 = filter_df(dff, filters[f]["condition1"], f)
                                dff2 = filter_df(dff, filters[f]["condition2"], f)
                                dff = pd.concat([dff1, dff2])
                        else:
                            dff = filter_df(dff, filters[f], f)
                    except:
                        pass

            if request["sortModel"]:
                sorting = []
                asc = []
                for sort in request["sortModel"]:
                    sorting.append(sort["colId"])
                    if sort["sort"] == "asc":
                        asc.append(True)
                    else:
                        asc.append(False)
                dff = dff.sort_values(by=sorting, ascending=asc)

            lines = len(dff.index)
            if lines == 0:
                lines = 1

            partial = dff.iloc[request["startRow"]: request["endRow"]]
            return {"rowData": partial.to_dict("records"), "rowCount": lines}


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
            Input('date-picker-single', 'value'),
            Input('query-2a-grid', 'filterModel'),
            Input("dropdown-color-2a", 'value'),            
        ],         
    )
    def update_graph2a(date_value, filter_modal, metric):
        # if TAB_VIEW != active_tab:
        #     return {}
        print("[INFO] query 2 - update_graph2a: ")

        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
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
        
        Output('query-2b-grid', "getRowsResponse"),
        [
            Input('date-picker-single', 'value'),
            Input("query-2b-grid", "getRowsRequest"),
        ],        
    )
    def update_grid2b(date_value, request):
        # if TAB_VIEW != active_tab:
        #     return [{}]

        print("[INFO] query 2 - update_table2b: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
        if df.empty:
            return [{}]
        
        dff = df.groupby('org_clean').agg({
            'ip_str': lambda x: list(x),
            'cve_id': lambda x: list(x),
            'cpe_product': lambda x: list(x),
            'epss': 'max', 
        }).reset_index()

        # return aggregated_df.to_dict('records')
        if request:
            if request["filterModel"]:
                filters = request["filterModel"]
                for f in filters:
                    try:
                        if "operator" in filters[f]:
                            if filters[f]["operator"] == "AND":
                                dff = filter_df(dff, filters[f]["condition1"], f)
                                dff = filter_df(dff, filters[f]["condition2"], f)
                            else:
                                dff1 = filter_df(dff, filters[f]["condition1"], f)
                                dff2 = filter_df(dff, filters[f]["condition2"], f)
                                dff = pd.concat([dff1, dff2])
                        else:
                            dff = filter_df(dff, filters[f], f)
                    except:
                        pass

            if request["sortModel"]:
                sorting = []
                asc = []
                for sort in request["sortModel"]:
                    sorting.append(sort["colId"])
                    if sort["sort"] == "asc":
                        asc.append(True)
                    else:
                        asc.append(False)
                dff = dff.sort_values(by=sorting, ascending=asc)

            lines = len(dff.index)
            if lines == 0:
                lines = 1

            partial = dff.iloc[request["startRow"]: request["endRow"]]
            return {"rowData": partial.to_dict("records"), "rowCount": lines}

    @app.callback(
        Output('query-2b-graph', 'figure'),

        Input('date-picker-single', 'value'),
        Input('query-2b-grid', 'filterModel'),
        Input("dropdown-type-2b", 'value'),                 
    )
    def update_graph2b(date_value, filter_modal, metric):
        # if TAB_VIEW != active_tab:
        #     return {}
        print("[INFO] query 2 - update_graph2b: ")

        aggregated_df = dm.get_view_dataset(date_value, INPUT_DATA_V2)
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

            if len(stats_df) > 1000:
                stats_df.at[1000, "pdf"] = stats_df[1000:]['pdf'].sum() 
                stats_df.at[1000, "cdf"] = stats_df[1000:]['cdf'].sum() 
                stats_df = stats_df[:1001]
            

            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['pdf'], mode='lines', name='PDF'))
            fig.add_trace(go.Scatter(x=stats_df['epss'], y=stats_df['cdf'], mode='lines', name='CDF'))
            fig.update_layout(title='PDF and CDF of EPSS Score',
                            xaxis_title='EPSS score (by organization)',
                            yaxis_title='Probability',
                            showlegend=True)

        elif metric == "PDF/CDF - Distribution of the number of CVE by Organization":

            aggregated_df["n_cves"] = aggregated_df["cve_id"].apply(len)

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

        elif metric == "PDF/CDF - Distribution of the number of vulnerable Products by Organization":

            aggregated_df["n_products"] = aggregated_df["cpe_product"].apply(len)

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
                            )
        return fig
        
    @app.callback(        
        Output('query-5-ag', 'filterModel'),
        Output("query-2a-grid", "cellClicked"),        
        Input("query-2a-grid", "cellClicked"),        
    )
    def select_ip(cell):

        filter_opt = {}  
        # if (TAB_VIEW == active_tab) and cell:
        if cell:
            if cell.get("colId", "") == "ip_str":
                value = cell.get('value', "")
                filter_opt = {'ip_str': {'filterType': 'text', 'type': 'equals', 'filter': value}}

                return filter_opt, {}
        return filter_opt, {}
    

    @app.callback(
        Output('v2-content', 'children'),
        Input("url", "pathname"),
    )
    def tab_v2_select(pathname):
        if pathname == "/dashboard/v2a":
            print("aqui", pathname)
            return tab1_content
        elif pathname == "/dashboard/v2b":
            print("aqui", pathname)
            return tab2_content


    @app.callback(
        Output('query-2a-grid', 'filterModel'),
        Output("query-2b-grid", "cellClicked"),
        Output("url", "pathname"),
        Input("query-2b-grid", "cellClicked"),        
    )
    def select_org_records(cell):
        print(cell)
        filter_opt = {}  
        if cell:
            if cell.get("colId", "") == "org_clean":
                value = cell.get('value', "")
                filter_opt = {'org_clean': {'filterType': 'text', 'type': 'equals', 'filter': value}}

                return filter_opt, {}, "/dashboard/v2a"
        return filter_opt, {}, "/dashboard/v1"

df = pd.read_csv(
    "https://raw.githubusercontent.com/plotly/datasets/master/ag-grid/olympic-winners.csv"
)
df["index"] = df.index

columnDefs = [
    {"field": "athlete", "suppressHeaderMenuButton": True},
    {
        "field": "age",
        "filter": "agNumberColumnFilter",
        "filterParams": {
            "filterOptions": ["equals", "lessThan", "greaterThan"],
            "maxNumConditions": 1,
        },
    },
    {
        "field": "country",
        "filter": True
    },
    {
        "field": "year",
        "filter": "agNumberColumnFilter",

    },
    {"field": "athlete"},
    {"field": "date"},
    {"field": "sport", "suppressHeaderMenuButton": True},
    {"field": "total", "suppressHeaderMenuButton": True},
]

defaultColDef = {
    "flex": 1,
    "minWidth": 150,
    "sortable": True,
    "resizable": True,
    "floatingFilter": True,
}

# app.layout = html.Div(
#     [
#         dag.AgGrid(
#             id="infinite-row-sort-filter-select",
#             columnDefs=columnDefs,
#             defaultColDef=defaultColDef,
#             rowModelType="infinite",
#             dashGridOptions={
#                 # The number of rows rendered outside the viewable area the grid renders.
#                 "rowBuffer": 0,
#                 # How many blocks to keep in the store. Default is no limit, so every requested block is kept.
#                 "maxBlocksInCache": 2,
#                 "cacheBlockSize": 100,
#                 "cacheOverflowSize": 2,
#                 "maxConcurrentDatasourceRequests": 2,
#                 "infiniteInitialRowCount": 1,
#                 "rowSelection": "multiple",
#             },
#             getRowId="params.data.index",
#         ),
#     ],
# )

# operators = {
#     "greaterThanOrEqual": "ge",
#     "lessThanOrEqual": "le",
#     "lessThan": "lt",
#     "greaterThan": "gt",
#     "notEqual": "ne",
#     "equals": "eq",
# }


# def filter_df(dff, filter_model, col):
#     if "filter" in filter_model:
#         if filter_model["filterType"] == "date":
#             crit1 = filter_model["dateFrom"]
#             crit1 = pd.Series(crit1).astype(dff[col].dtype)[0]
#             if "dateTo" in filter_model:
#                 crit2 = filter_model["dateTo"]
#                 crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
#         else:
#             crit1 = filter_model["filter"]
#             crit1 = pd.Series(crit1).astype(dff[col].dtype)[0]
#             if "filterTo" in filter_model:
#                 crit2 = filter_model["filterTo"]
#                 crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
#     if "type" in filter_model:
#         if filter_model["type"] == "contains":
#             dff = dff.loc[dff[col].str.contains(crit1)]
#         elif filter_model["type"] == "notContains":
#             dff = dff.loc[~dff[col].str.contains(crit1)]
#         elif filter_model["type"] == "startsWith":
#             dff = dff.loc[dff[col].str.startswith(crit1)]
#         elif filter_model["type"] == "notStartsWith":
#             dff = dff.loc[~dff[col].str.startswith(crit1)]
#         elif filter_model["type"] == "endsWith":
#             dff = dff.loc[dff[col].str.endswith(crit1)]
#         elif filter_model["type"] == "notEndsWith":
#             dff = dff.loc[~dff[col].str.endswith(crit1)]
#         elif filter_model["type"] == "inRange":
#             if filter_model["filterType"] == "date":
#                 dff = dff.loc[
#                     dff[col].astype("datetime64[ns]").between_time(crit1, crit2)
#                 ]
#             else:
#                 dff = dff.loc[dff[col].between(crit1, crit2)]
#         elif filter_model["type"] == "blank":
#             dff = dff.loc[dff[col].isnull()]
#         elif filter_model["type"] == "notBlank":
#             dff = dff.loc[~dff[col].isnull()]
#         else:
#             dff = dff.loc[getattr(dff[col], operators[filter_model["type"]])(crit1)]
#     elif filter_model["filterType"] == "set":
#         dff = dff.loc[dff[col].astype("string").isin(filter_model["values"])]
#     return dff


# @callback(
#     Output("infinite-row-sort-filter-select", "getRowsResponse"),
#     Input("infinite-row-sort-filter-select", "getRowsRequest"),
# )
# def infinite_scroll(request):
#     dff = df.copy()

#     if request:
#         if request["filterModel"]:
#             filters = request["filterModel"]
#             for f in filters:
#                 try:
#                     if "operator" in filters[f]:
#                         if filters[f]["operator"] == "AND":
#                             dff = filter_df(dff, filters[f]["condition1"], f)
#                             dff = filter_df(dff, filters[f]["condition2"], f)
#                         else:
#                             dff1 = filter_df(dff, filters[f]["condition1"], f)
#                             dff2 = filter_df(dff, filters[f]["condition2"], f)
#                             dff = pd.concat([dff1, dff2])
#                     else:
#                         dff = filter_df(dff, filters[f], f)
#                 except:
#                     pass

#         if request["sortModel"]:
#             sorting = []
#             asc = []
#             for sort in request["sortModel"]:
#                 sorting.append(sort["colId"])
#                 if sort["sort"] == "asc":
#                     asc.append(True)
#                 else:
#                     asc.append(False)
#             dff = dff.sort_values(by=sorting, ascending=asc)

#         lines = len(dff.index)
#         if lines == 0:
#             lines = 1

#         partial = dff.iloc[request["startRow"]: request["endRow"]]
#         return {"rowData": partial.to_dict("records"), "rowCount": lines}
