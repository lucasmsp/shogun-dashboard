from dash import html, dcc, dash_table, callback_context, ctx, no_update
from dash.dependencies import Output, Input, State
import dash_bootstrap_components as dbc
import dash_ag_grid as dag
from project.auxiliar import gen_subgraphs, header_mapping, gen_columns_def, logging

import itertools
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import re
import heapq


INPUT_DATA_V6 = 'as'

def register_layout_query(filter_modal={}):

    special_config = {
        'asn': {'pinned': 'left'},
        'as_announcing_addresses': {
            'tooltipField': 'as_announcing_prefixes',
            'tooltipComponent': 'CustomTooltipAddressesV6'
        },
        'as_country_name': {'tooltipField': 'n_cities', 'tooltipComponent': 'CustomTooltipCountryNameV6'}
    }
    as_info_columns, raw_data1 = gen_columns_def(["asn", "as_rank", "as_announcing_addresses", "as_country_name"],
                                        special_configs=special_config)
    org_columns, raw_data2 = gen_columns_def(["as_org_name", "as_org_country_name"])
    columns = [
        {
            'headerName': 'AS Info',
            'children': list(as_info_columns.values())
        },
        {
            'headerName': 'Organization Owner',
            'children': list(org_columns.values())
        },
    ]

    special_config = {
        "avg_cvss": {
            'tooltipField':  'min_cvss',
            "tooltipComponent": "CustomTooltipCvssV6"

        },
        "avg_epss": {
            'tooltipField': 'min_epss',
            "tooltipComponent": "CustomTooltipEpssV6",
        },
        'n_cves': { "headerTooltip":
                        "Clicking a cell filters the data based on the selected value, "
                        "showing the top 100 most recent CVE codes associated with the chosen entry."}
    }

    remaining_columns, raw_data3 = gen_columns_def(["vulns_cvss_avg", "vulns_epss_avg", "n_orgs", "n_ips", "n_cves"],
                                            special_configs=special_config)
    columns += list(remaining_columns.values())
    raw_data = raw_data1 + raw_data2 + raw_data3 # is it really necessary?


    aggrid = dag.AgGrid(
        id="query-6-table",
        #rowData=raw_data,
        columnDefs=columns,
        defaultColDef={"flex": 1, "filter": True, "resizable": True},
        columnSize="sizeToFit",
        filterModel=filter_modal,
        dashGridOptions={
            "rowSelection": "single",
            'tooltipShowDelay': 0,
            'tooltipHideDelay': 50000,
            "animateRows": False
        },
    )

    elements = [
        dbc.Row(
            html.Div([
                html.H1(children="View 6 - AS summary", className='wrapper', style={'textAlign': 'center'}),
                html.H2(
                    children="This visualization allows the analysis of Autonomous Systems.",
                    style={'fontSize': '20px', 'top-padding': '40px', 'bottom-padding': '40px'}
                )
            ])
        ),
        dcc.Loading([aggrid]),
        dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
        dbc.Row([html.Div(id='query-6-graph', children=[])])
    ]

    tab6_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=elements)], className="wrapper"),
        ),
        className="mt-3",
        id="tab6_content_asn"
    )

    return tab6_content

def register_callback_query(dm, app):

    @app.callback(
        Output('query-6-table', "rowData"),
        Input('date-picker-single', 'value')
    )
    def update_grid6(date_value):
        logging.info("query6_as - update_grid6: " + date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA_V6)

        if df.empty:
            return [{}]

        # Conversão de tipos
        df['as_announcing_prefixes'] = df['as_announcing_prefixes'].fillna(-1).astype(int)
        df['as_announcing_addresses'] = df['as_announcing_addresses'].fillna(-1).astype(int)
        df["n_cities"] = df["city_list"].apply(lambda x: len(x))
        df["n_cisa"] = df["vulns_cisa_list"].apply(lambda x: len(x))
        df["n_cves"] = df["vulns_cve_list"].apply(lambda x: len(x))

        # Filtrar apenas as colunas relevantes
        df_filtered = df[['asn', 'as_org_name', 'as_country_name', 'as_announcing_prefixes',
                          'vulns_cvss_avg', 'vulns_cvss_min', 'vulns_cvss_max',
                          'vulns_epss_avg', 'vulns_epss_min', 'vulns_epss_max',
                          'as_rank', 'n_orgs', 'as_org_country_name', 'as_announcing_addresses',
                          'as_seen', 'n_cities', 'n_ips', 'n_cisa', 'n_cves']]

        return df_filtered.to_dict('records')

    @app.callback(
        Output("query-6-graph", "children"),
        Input('date-picker-single', 'value')
    )
    def update_asn_chart(date_value):
        logging.info("query6_as - update_asn_chart: " + date_value)

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
        for cities_list in df['city_list']:
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
            labels={'state': 'State', 'n_ips': 'Number of IPs'},
            title='# IPs per Brazilian state'
        )

        graphs = [dcc.Graph(figure=fig_horizontal_bar, config={'displayModeBar': False, 'scrollZoom': False})]

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
                "y_column": "vulns_cvss_avg", "graph_type": "bar plot", "y_label": "Average CVSS",
                'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
            },
            "Bar plot - Average EPSS by ASN (Top 10 IPs)": {
                "y_column": "vulns_epss_avg", "graph_type": "bar plot", "y_label": "Average EPSS",
                'x_column': 'asn', 'x_label': "ASN", 'df': df_top_ips
            }
        }
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
        State('date-picker-single', 'value'),
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
                return "/dashboard/cve", filter_opt

        return no_update, no_update
