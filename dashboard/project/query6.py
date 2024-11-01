from dash import html, dcc, dash_table, callback_context, ctx, no_update
from dash.dependencies import Output, Input, State
import dash_bootstrap_components as dbc
import dash_ag_grid as dag
from project.auxiliar import gen_subgraphs, header_mapping

import itertools
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import re


INPUT_DATA_V6 = '4'

def register_layout_query(filter_modal={}):
    
    columnDefs = [
        {
            'headerName': 'AS Info',
            'children':[
                {
                    'headerName': 'ASN',
                    "field": "asn",
                    # "tooltipComponent": "CustomTooltipAsnV6"
                    "cellStyle": {
                        "styleConditions": [
                            {
                                "condition": "params.data.as_seen == 'True'",
                                "style": {"backgroundColor": "lightgreen"},
                            },
                            {
                                "condition": "params.data.as_seen == 'False'",
                                "style": {"backgroundColor": "lightcoral"},
                            },

                        ],
                    }
                },
                {
                    'headerName': 'Rank',
                    "field": "as_rank",
                    # "tooltipComponent": "CustomTooltipAsnV6"
                },
                {
                    'headerName': 'Addresses',
                    "field": "as_announcing_addresses",
                },
                {
                    'headerName': 'Country',
                    "field": "as_country_name",
                    "tooltipComponent": "CustomTooltipCountryNameV6",
                    'tooltipField': 'n_cities',
                }
            ]
        },
        {
            'headerName': 'Organization Owner',
            'children':[
                {
                    'headerName': 'Name',
                    "field": "as_org_name",
                    # "tooltipComponent": "CustomTooltipAsnV6"
                },
                {
                    'headerName': 'Country',
                    "field": "as_org_country_name",
                    # "tooltipComponent": "CustomTooltipAsnV6"
                },
            ]
        },
        {
            'headerName': 'Avg CVSS',
            "field": "avg_cvss",
            'tooltipField': 'min_cvss',
            # 'headerTooltip': "Avg CVSS - Tooltip shows min and max CVSS",
            "tooltipComponent": "CustomTooltipCvssV6",
            "valueFormatter": {"function": "params.value.toFixed(4)"}
        },
        {
            'headerName': 'Avg EPSS',
            "field": "avg_epss",
            'tooltipField': 'min_epss',
            # 'headerTooltip': "Avg EPSS - Tooltip shows min and max EPSS",
            "tooltipComponent": "CustomTooltipEpssV6",
            "valueFormatter": {"function": "params.value.toFixed(4)"}
        },
        {
            'headerName': '# Orgs',
            "field": "n_orgs",
            # 'headerTooltip': "Avg EPSS - Tooltip shows min and max EPSS",
            # "tooltipComponent": "CustomTooltipEpssV6",
            # "valueFormatter": {"function": "params.value.toFixed(4)"}
        },
        {
            'headerName': '# IPs',
            "field": "n_ips",
            # 'headerTooltip': "Avg EPSS - Tooltip shows min and max EPSS",
            # "tooltipComponent": "CustomTooltipEpssV6",
            # "valueFormatter": {"function": "params.value.toFixed(4)"}
        },
        {
            'headerName': '# CVEs',
            "field": "n_cve",
            # 'headerTooltip': "Avg EPSS - Tooltip shows min and max EPSS",
            # "tooltipComponent": "CustomTooltipEpssV6",
            # "valueFormatter": {"function": "params.value.toFixed(4)"}
        },
    ]
    q6 = [
        html.H1(children="View 6 - AS summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
                dbc.Row(


                    # dag.AgGrid(
                    #     id='query-6-table',
                    #     columnDefs=[
                    #         {"headerName": 'Oganization', "field": "as_org_name", "flex": 1}, 
                    #         {"headerName": 'ASN', "field": 'asn', "flex": 1},
                    #         {"headerName": 'Prefixes', "field": 'as_announcing_prefixes', "flex": 1},
                    #         {"headerName": 'Addresses', "field": 'as_announcing_addresses', "flex": 1},
                    #         {"headerName": 'Seen', "field": 'as_seen', "flex": 1},
                    #     ],
                    #     rowData = [{"as_org_name": "Processing...", "asn": 0, "as_announcing_prefixes": 0, "as_announcing_addresses": 0}],
                    #     defaultColDef={"flex": 1, "filter": True},
                    #     columnSize="sizeToFit",
                    #     columnSizeOptions= {"skipHeader": False},
                    #     style={"height": 260},
                    #     getRowStyle = {
                    #         "styleConditions": [
                    #             {
                    #                 "condition": "params.data.as_seen == 'True'",
                    #                 "style": {"backgroundColor": "lightgreen", "color": "black"},
                    #             },
                    #             {
                    #                 "condition": "params.data.as_seen == 'False'",
                    #                 "style": {"backgroundColor": "lightcoral", "color": "black"},
                    #             },
                    #         ]
                    #     }
                    # ),



                    # dag.AgGrid(
                    #     id='query-6-table',
                    #     columnDefs=[
                    #         {"headerName": 'ASN', "field": "asn", "flex": 1, 
                    #         "tooltipField": 'as_rank', 
                    #         "headerTooltip": "ASN - Autonomous System Number (tooltip shows ASN rank)"}, 
                            
                    #         {"headerName": 'Organization', "field": "as_org_name", "flex": 1, 
                    #         "tooltipField": 'n_orgs', 
                    #         "headerTooltip": "Name of the organization (tooltip shows the number of organizations)"}, 
                            
                    #         {"headerName": 'Country', "field": "as_country_name", "flex": 1, 
                    #         "tooltipField": 'as_org_country_name', 
                    #         "headerTooltip": "Country of the AS (tooltip shows the organization country name)"}, 
                            
                    #         {"headerName": 'Prefixes', "field": "as_announcing_prefixes", "flex": 1, 
                    #         "tooltipField": 'as_announcing_addresses', 
                    #         "headerTooltip": "Number of prefixes (tooltip shows the number of addresses)"}, 
                            
                    #         {"headerName": 'Avg CVSS', "field": "avg_cvss", "flex": 1, 
                    #         "tooltipField": ['min_cvss', 'max_cvss'], 
                    #         "headerTooltip": "Average CVSS score (tooltip shows min and max CVSS)"}, 
                            
                    #         {"headerName": 'Avg EPSS', "field": "avg_epss", "flex": 1, 
                    #         "tooltipField": ['min_epss', 'max_epss'], 
                    #         "headerTooltip": "Average EPSS score (tooltip shows min and max EPSS)"}
                    #     ],
                    #     defaultColDef={"flex": 1, "filter": True, "tooltipComponent": "customTooltip"},
                    #     columnSize="sizeToFit",
                    #     columnSizeOptions= {"skipHeader": False},
                    #     style={"height": 260},
                    #     getRowStyle={
                    #         "function": """
                    #             (params) => {
                    #                 if (params.data.as_country_name !== params.data.as_org_country_name) {
                    #                     return { 'backgroundColor': 'lightyellow', 'color': 'black' };
                    #                  }
                    #                 return {};
                    #             }
                    #         """
                    #     }
                    # )
                    
                    dag.AgGrid(
                        id="query-6-table",
                        columnDefs=columnDefs,
                        defaultColDef={"flex": 1, "filter": True, "resizable": True},
                        columnSize="sizeToFit",
                        dashGridOptions={'tooltipShowDelay': 0, 'tooltipHideDelay': 50000},
                        style={"height": 360},
                        # getRowStyle={
                        #     "function": """
                        #         (params) => {
                        #             if (params.data.as_country_name !== params.data.as_org_country_name) {
                        #                 return { 'backgroundColor': 'lightyellow', 'color': 'black' };
                        #             }
                        #             return {};
                        #         }
                        #     """,
                        #     "styleConditions": [
                        #         {
                        #             "condition": "params.data.as_seen == 'True'",
                        #             "style": {"backgroundColor": "lightgreen", "color": "black"},
                        #         },
                        #         {
                        #             "condition": "params.data.as_seen == 'False'",
                        #             "style": {"backgroundColor": "lightcoral", "color": "black"},
                        #         },
                        #     ]   
                        # }
                    )
                ),
                dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
                dbc.Row([html.Div(id='query-6-graph', children=[])])

                
                # dbc.Row(
                #     [
                #         html.H4(children="Choose a type of graph: ", className='wrapper', style={'textAlign': 'Left'}),
                #         dcc.Dropdown(
                #             id="query-6-dropdown",
                #             options=[
                #                 "Bar plot - Number of CVEs by EPSS Rank", 
                #                 "Bar plot - Number of organizations by EPSS Rank",
                #                 "Bar plot - Number of IPs by EPSS Rank",
                #                 "CDF plot - Number of CVEs by EPSS Rank",
                #                 "PDF plot - Number of CVEs by EPSS Rank"
                #             ],
                #             value="Bar plot - Number of CVEs by EPSS Rank",
                #             clearable=False,
                #         ),
                #         dcc.Graph(
                #             id="query-6-graph",
                #             config={
                #                 'displayModeBar': False,
                #                 'scrollZoom': False
                #             }, 
                #         ),
                #     ]
                # )
            ]
        )
    ]

    layout = dbc.Card(
        dbc.CardBody(
            html.Div(
                q6,
                className="wrapper"
            )
        ),
        className="mt-3",
        id="tab6_content_asn"
    )

    return layout

def register_callback_query(dm, app):
    
    # @app.callback(
    #     Output('query-6-table', "rowData"),
    #     [
    #         Input('date-picker-single', 'value'),
    #     ]
    # )
    # def update_grid2a(date_value):

    #     print("[INFO] query 2 - update_table2a: ", date_value)
    #     df = dm.get_view_dataset(date_value, INPUT_DATA_V6)

    #     if df.empty:
    #         return [{}]
        
    #     df['as_announcing_prefixes'] = df['as_announcing_prefixes'].astype(int)
    #     df['as_announcing_addresses'] = df['as_announcing_addresses'].astype(int)
    #     df['asn'] = df['asn'].str.replace('AS', '').astype(int)
        
        
    #     return df.to_dict('records')

    @app.callback(
        Output('query-6-table', "rowData"),
        [
            Input('date-picker-single', 'value'),
        ]
    )
    def update_grid6(date_value):
        print("[INFO] query 2 - update_table2a: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA_V6)

        if df.empty:
            return [{}]

        # Conversão de tipos
        df['as_announcing_prefixes'] = df['as_announcing_prefixes'].astype(int)
        df['as_announcing_addresses'] = df['as_announcing_addresses'].astype(int)
        df['asn'] = df['asn'].str.replace('AS', '').astype(int)
        df["n_cities"] = df["cities"].apply(lambda x: len(x))
        df["n_cisa"] = df["cisa_vulns"].apply(lambda x: len(x))
        df["n_cve"] = df["cve_list"].apply(lambda x: len(x))
        
        # Filtrar apenas as colunas relevantes
        df_filtered = df[['asn', 'as_org_name', 'as_country_name', 'as_announcing_prefixes', 'avg_cvss', 'avg_epss',
                        'as_rank', 'n_orgs', 'as_org_country_name', 'as_announcing_addresses', 'min_cvss', 'max_cvss', 
                        'min_epss', 'max_epss', 'as_seen', 'n_cities', 'n_ips', 'n_cisa', 'n_cve']]
        
        return df_filtered.to_dict('records')
    
    @app.callback(
        Output("query-6-graph", "children"),
        Input('date-picker-single', 'value')
    )
    def update_asn_chart(date_value):
        print(f"[INFO][query_asn] update_asn_chart: {date_value}")
        df = dm.get_view_dataset(date_value, INPUT_DATA_V6)
        
        if df.empty:
            return []

        df_top_ips = df.nlargest(10, 'n_ips')
        df_top_orgs = df.nlargest(10, 'n_orgs')

        graphs_type = {
            "Bar plot - Top 10 ASN by Number of IPs":
                { "y_column": "n_ips", "graph_type": "bar plot", "y_label": "# IPs",
                    'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips},
            "Bar plot - Top 10 ASN by Number of Organizations":
                {"y_column": "n_orgs", "graph_type": "bar plot", "y_label": "# Orgs",
                    'x_column': 'asn', 'x_label': "ASN", 'df': df_top_orgs},
            "Bar plot - Average CVSS by ASN (Top 10 IPs)":
                {"y_column": "avg_cvss", "graph_type": "bar plot", "y_label": "Average CVSS",
                    'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips},
            "Bar plot - Average EPSS by ASN (Top 10 IPs)":
                {"y_column": "avg_epss", "graph_type": "bar plot", "y_label": "Average EPSS",
                    'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips},
            # "PDF plot - Average CVSS by ASN (Top 10 IPs)":
            #     {"y_column": "avg_cvss", "graph_type": "pdf plot", "y_label": "Avg CVSS",
            #         'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips},
            # "CDF plot - Average EPS by ASN (Top 10 IPs)":
            #     {"y_column": "avg_epss", "graph_type": "cdf plot", "y_label": "Avg EPSS",
            #         'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips},
        }

        graphs = []
        for title, configs in graphs_type.items():
            y_column = configs['y_column']
            x_column = configs['x_column']
            y_label = configs['y_label']
            x_label = configs['x_label']
            graph_type = configs['graph_type']
            df_filtered = configs['df']  # Usa o dataframe filtrado (Top 10)

            if graph_type == "bar plot":
                fig = px.bar(df_filtered,
                            x=x_column,
                            y=y_column,
                            barmode="group",
                            labels={
                                x_column: x_label,
                                y_column: y_label
                            },
                            title=title
                )
            elif graph_type == "pdf plot":
                df_filtered['pdf'] = df_filtered[y_column] / sum(df_filtered[y_column])
                df_filtered = df_filtered.reset_index()
                fig = px.line(df_filtered,
                            x=x_column,
                            y='pdf',
                            range_y=(0, 1),
                            title=title,
                            labels={
                                x_column: x_label,
                                'pdf': "PDF"
                            }
                )
            else:  # cdf plot
                df_filtered['pdf'] = df_filtered[y_column] / sum(df_filtered[y_column])
                df_filtered['cdf'] = df_filtered['pdf'].cumsum()
                df_filtered = df_filtered.reset_index()
                fig = px.line(df_filtered,
                            x=x_column,
                            y='cdf',
                            range_y=(0, 1),
                            title=title,
                            labels={
                                x_column: x_label,
                                'cdf': "CDF"
                            }
                )
            
            graph = dcc.Graph(figure=fig,
                            config={
                                'displayModeBar': False,
                                'scrollZoom': False
                            }
            )
            graphs.append(graph)
        
        children = gen_subgraphs(n_cols=2, graphs=graphs)
        return children
        


