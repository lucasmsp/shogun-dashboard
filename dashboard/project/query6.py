from dash import html, dcc, dash_table, callback_context, ctx, no_update
from dash.dependencies import Output, Input, State
import dash_bootstrap_components as dbc
import dash_ag_grid as dag
from project.auxiliar import gen_subgraphs, header_mapping, gen_columns_def

import itertools
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import re
import heapq


INPUT_DATA_V6 = '4'

def register_layout_query(filter_modal={}):

    columnDefs = [
        {
            'headerName': 'AS Info',
            'children': gen_columns_def(["asn", "as_rank", "as_announcing_addresses", "as_country_name"])[0]
        },
        {
            'headerName': 'Organization Owner',
            'children': gen_columns_def(["as_org_name", "as_org_country_name"])[0]
        },
    ]

    for i in gen_columns_def(["avg_cvss", "avg_epss", "n_orgs", "n_ips", "n_cves"])[0]:
        columnDefs.append(i)

    columnDefs[0]['children'][0]['cellStyle'] = {
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
    columnDefs[0]['children'][2]['tooltipField'] = 'as_announcing_prefixes'
    columnDefs[0]['children'][2]['tooltipComponent'] = 'CustomTooltipAddressesV6'
    columnDefs[0]['children'][3]['tooltipField'] = 'n_cities'
    columnDefs[0]['children'][3]['tooltipComponent'] = 'CustomTooltipCountryNameV6'
    columnDefs[2]['tooltipField'] = 'min_cvss'
    columnDefs[2]["tooltipComponent"] = "CustomTooltipCvssV6"
    columnDefs[2]["valueFormatter"] = {"function": "params.value.toFixed(4)"}
    columnDefs[2]["cellStyle"] = {
        "styleConditions": [
            {
                "condition": "params.data.avg_cvss >= 0 && params.data.avg_cvss <= 2",
                "style": {"backgroundColor": "#FFD700"},
            },
            {
                "condition": "params.data.avg_cvss > 2 && params.data.avg_cvss <= 4",
                "style": {"backgroundColor": "#FFA500"},
            },
            {
                "condition": "params.data.avg_cvss > 4 && params.data.avg_cvss <= 6",
                "style": {"backgroundColor": "#FF8C00"},
            },
            {
                "condition": "params.data.avg_cvss > 6 && params.data.avg_cvss <= 8",
                "style": {"backgroundColor": "#FF6347"},
            },
            {
                "condition": "params.data.avg_cvss > 8 && params.data.avg_cvss <= 10",
                "style": {"backgroundColor": "#FF4500"},
            },
        ],
    }
    columnDefs[3]['tooltipField'] = 'min_epss'
    columnDefs[3]["tooltipComponent"] = "CustomTooltipEpssV6"
    columnDefs[3]["valueFormatter"] = {"function": "params.value.toFixed(4)"}
    columnDefs[3]["cellStyle"] = {
        "styleConditions": [
            {
                "condition": "params.data.avg_epss >= 0 && params.data.avg_epss <= 0.2",
                "style": {"backgroundColor": "#FFD700"},
            },
            {
                "condition": "params.data.avg_epss > 0.2 && params.data.avg_epss <= 0.4",
                "style": {"backgroundColor": "#FFA500"},
            },
            {
                "condition": "params.data.avg_epss > 0.4 && params.data.avg_epss <= 0.6",
                "style": {"backgroundColor": "#FF8C00"},
            },
            {
                "condition": "params.data.avg_epss > 0.6 && params.data.avg_epss <= 0.8",
                "style": {"backgroundColor": "#FF6347"},
            },
            {
                "condition": "params.data.avg_epss > 0.8 && params.data.avg_epss <= 1",
                "style": {"backgroundColor": "#FF4500"},
            },
        ],
    }
    columnDefs[6]["headerTooltip"] = "Clicking a cell filters the data based on the selected value, " \
                                     "showing the top 100 most recent CVE codes associated with the chosen entry."

    
    q6 = [
        html.H1(children="View 6 - AS summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
                dbc.Row(
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
        df["n_cities"] = df["cities"].apply(lambda x: len(x))
        df["n_cisa"] = df["cisa_vulns"].apply(lambda x: len(x))
        df["n_cves"] = df["cve_list"].apply(lambda x: len(x))
        
        # Filtrar apenas as colunas relevantes
        df_filtered = df[['asn', 'as_org_name', 'as_country_name', 'as_announcing_prefixes', 'avg_cvss', 'avg_epss',
                        'as_rank', 'n_orgs', 'as_org_country_name', 'as_announcing_addresses', 'min_cvss', 'max_cvss', 
                        'min_epss', 'max_epss', 'as_seen', 'n_cities', 'n_ips', 'n_cisa', 'n_cves']]
        
        return df_filtered.to_dict('records')
    
        
    # @app.callback(
    #     Output("query-6-graph", "children"),
    #     Input('date-picker-single', 'value')
    # )
    # def update_asn_chart(date_value):
    #     print(f"[INFO][query_asn] update_asn_chart: {date_value}")
    #     df = dm.get_view_dataset(date_value, INPUT_DATA_V6)

    #     if df.empty:
    #         return []

    #     df_top_ips = df.nlargest(10, 'n_ips')
    #     df_top_orgs = df.nlargest(10, 'n_orgs')

    #     # Função para extrair o estado das cidades no formato "Cidade, UF"
    #     def extract_state(city):
    #         if pd.isna(city):
    #             return None
    #         try:
    #             return city.split(", ")[-1]
    #         except IndexError:
    #             return None

    #     all_states = []
    #     for cities_list in df['cities']:
    #         for city in cities_list:
    #             state = extract_state(city)
    #             if state:
    #                 all_states.append(state)

    #     state_df = pd.DataFrame(all_states, columns=['state'])
    #     df_ips_by_state = state_df.value_counts().reset_index(name='n_ips')
    #     df_ips_by_state.columns = ['state', 'n_ips']
    #     df_ips_by_state = df_ips_by_state.sort_values(by='n_ips', ascending=True).tail(10)


    #     fig_horizontal_bar = px.bar(
    #         df_ips_by_state,
    #         y='state',
    #         x='n_ips',
    #         orientation='h',
    #         labels={'state': 'Estado', 'n_ips': 'Número de IPs'},
    #         title='Número de IPs por Estado Brasileiro'
    #     )

    #     graphs_type = {
    #         "Bar plot - Top 10 ASN by Number of IPs": {
    #             "y_column": "n_ips", "graph_type": "bar plot", "y_label": "# IPs",
    #             'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
    #         },
    #         "Bar plot - Top 10 ASN by Number of Organizations": {
    #             "y_column": "n_orgs", "graph_type": "bar plot", "y_label": "# Orgs",
    #             'x_column': 'asn', 'x_label': "ASN", 'df': df_top_orgs
    #         },
    #         "Bar plot - Average CVSS by ASN (Top 10 IPs)": {
    #             "y_column": "avg_cvss", "graph_type": "bar plot", "y_label": "Average CVSS",
    #             'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
    #         },
    #         "Bar plot - Average EPSS by ASN (Top 10 IPs)": {
    #             "y_column": "avg_epss", "graph_type": "bar plot", "y_label": "Average EPSS",
    #             'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
    #         }
    #     }

    #     graphs = []
    #     graphs.append(dcc.Graph(figure=fig_horizontal_bar, config={'displayModeBar': False, 'scrollZoom': False}))
    #     for title, configs in graphs_type.items():
    #         y_column = configs['y_column']
    #         x_column = configs['x_column']
    #         y_label = configs['y_label']
    #         x_label = configs['x_label']
    #         graph_type = configs['graph_type']
    #         df_filtered = configs['df']
    #         if graph_type == "bar plot":
    #             fig = px.bar(df_filtered,
    #                         x=x_column,
    #                         y=y_column,
    #                         barmode="group",
    #                         labels={x_column: x_label, y_column: y_label},
    #                         title=title)
    #         graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
    #         graphs.append(graph)


    #     children = gen_subgraphs(n_cols=2, graphs=graphs)
    #     return children

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

        # Função para extrair o estado das cidades no formato "Cidade, UF"
        def extract_state(city):
            if pd.isna(city):
                return None
            try:
                return city.split(", ")[-1]
            except IndexError:
                return None

        all_states = []
        for cities_list in df['cities']:
            for city in cities_list:
                state = extract_state(city)
                if state:
                    all_states.append(state)

        state_df = pd.DataFrame(all_states, columns=['state'])
        df_ips_by_state = state_df.value_counts().reset_index(name='n_ips')
        df_ips_by_state.columns = ['state', 'n_ips']
        df_ips_by_state = df_ips_by_state.sort_values(by='n_ips', ascending=True).tail(10)
        custom_scale = [
            (0.0, "rgb(0, 73, 111)"),  # Meio do gradiente
            (1.0, "rgb(94, 0, 0)")     # Fim do gradiente (valor máximo)
        ]
        # Gráfico horizontal com cores baseadas na quantidade de IPs
        fig_horizontal_bar = px.bar(
            df_ips_by_state,
            y='state',
            x='n_ips',
            orientation='h',
            color='n_ips',  # Adicionando cores baseadas na quantidade
            color_continuous_scale=custom_scale,  # Escolha de escala de cores
            labels={'state': 'Estado', 'n_ips': 'Número de IPs'},
            title='Número de IPs por Estado Brasileiro'
        )

        graphs_type = {
            "Bar plot - Top 10 ASN by Number of IPs": {
                "y_column": "n_ips", "graph_type": "bar plot", "y_label": "# IPs",
                'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
            },
            "Bar plot - Top 10 ASN by Number of Organizations": {
                "y_column": "n_orgs", "graph_type": "bar plot", "y_label": "# Orgs",
                'x_column': 'asn', 'x_label': "ASN", 'df': df_top_orgs
            },
            "Bar plot - Average CVSS by ASN (Top 10 IPs)": {
                "y_column": "avg_cvss", "graph_type": "bar plot", "y_label": "Average CVSS",
                'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
            },
            "Bar plot - Average EPSS by ASN (Top 10 IPs)": {
                "y_column": "avg_epss", "graph_type": "bar plot", "y_label": "Average EPSS",
                'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
            }
        }

        graphs = []
        graphs.append(dcc.Graph(figure=fig_horizontal_bar, config={'displayModeBar': False, 'scrollZoom': False}))
        for title, configs in graphs_type.items():
            y_column = configs['y_column']
            x_column = configs['x_column']
            y_label = configs['y_label']
            x_label = configs['x_label']
            graph_type = configs['graph_type']
            df_filtered = configs['df']
            if graph_type == "bar plot":
                # Gráfico de barras com cores baseadas na quantidade
                fig = px.bar(
                    df_filtered,
                    x=x_column,
                    y=y_column,
                    color=y_column,  # Adicionando cores baseadas no valor de y_column
                    color_continuous_scale=custom_scale,  # Escolha de escala de cores
                    barmode="group",
                    labels={x_column: x_label, y_column: y_label},
                    title=title
                )
                graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
                graphs.append(graph)

        children = gen_subgraphs(n_cols=2, graphs=graphs)
        return children

    
    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-6-table", "cellClicked"),
        Input('date-picker-single', 'value'),
        prevent_initial_call=True,
    )
    def filter_asn(cell, date_value):

        df = dm.get_view_dataset(date_value, INPUT_DATA_V6)

        if cell:
            if cell.get("colId", "") == "asn":
                filter_opt = {
                    "query-5-ag": {'asn': {'filterType': 'text', 'type': 'equals', 'filter': cell.get("value", "")}}}
                return "/dashboard/report", filter_opt
            elif cell.get("colId", "") == "n_cves":
                row_id = int(cell.get("rowId", 0))
                cve_list = df.at[row_id, "cve_list"]
                top_100_cves = heapq.nlargest(100, cve_list)
                filter_opt = {
                    "query-3-ag": {
                        'vulns_cve_id': {
                            "filterType": "text",
                            "operator": "OR",
                            "conditions":[
                                {
                                    "filter": cve,
                                    "filterType": "text",
                                    "type": "equals"
                                } for cve in top_100_cves
                            ]
                        }
                    }
                }
                return "/dashboard/view3", filter_opt
            return no_update, no_update
        return no_update, no_update
    