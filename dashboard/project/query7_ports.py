from dash import html, dcc
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input

import plotly.express as px
import dash_ag_grid as dag


from project.auxiliar import gen_subgraphs, gen_columns_def

INPUT_DATA = '5'


def register_layout_query(filter_modal={}):
    columns, raw_data = gen_columns_def(['port', 'vulns_epss_max', 'vulns_cvss_score_max',
                                         'n_vulns_in_cisa', 'n_products'])

    for column in columns:
        column["resizable"] = False

    aggrid = dag.AgGrid(
        id='query-7-table',
        rowData=raw_data,
        columnDefs=columns,
        defaultColDef={"flex": 1, "filter": True},
        columnSize="responsiveSizeToFit",
        columnSizeOptions={"skipHeader": False},
        dashGridOptions={
            "rowSelection": "single",
            'tooltipInteraction': True,
            'tooltipShowDelay': 10,
            'tooltipHideDelay': 10000,
            "animateRows": False,
        }
    )

    elements = [
        html.H1(children="View 7 - Vulnerable Ports Summary", className='wrapper', style={'textAlign': 'center'}),
        dbc.Container(
            [
                dbc.Row(aggrid),
                dbc.Row(
                    dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
                dbc.Row([html.Div(id='query-7-graph', children=[])])
            ]
        )
    ]

    tab7_content = dbc.Card(
        dbc.CardBody(html.Div(children=[dbc.Row(children=elements)], className="wrapper")),
        className="mt-3",
        id="tab7_content"
    )

    return tab7_content


def register_callback_query(dm, app):
    @app.callback(
        Output('query-7-table', "rowData"),
        Input('date-picker-single', 'value')
    )
    def update_table7(date_value):
        print(f"[INFO][query7] update_table7: {date_value}")
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        return df.to_dict('records')
    
    @app.callback(
        Output("query-7-graph", "children"),
        Input('date-picker-single', 'value')
    )
    def update_vulnerability_charts(date_value):
        print(f"[INFO][query_graph] update_vulnerability_charts: {date_value}")
        df = dm.get_view_dataset(date_value, INPUT_DATA)

        if df.empty:
            return []

        # Gráfico de barra: n_vulns (CISA e Known) por porta (Top 20)
        df_vulns_by_port = df[['port', 'n_vulns_in_cisa', 'n_vulns_cisa_knownRansomwareCampaignUse']].copy()
        df_vulns_by_port = df_vulns_by_port.groupby('port').sum().reset_index()
        df_vulns_by_port = df_vulns_by_port.nlargest(20, ['n_vulns_in_cisa', 'n_vulns_cisa_knownRansomwareCampaignUse'])
        df_vulns_by_port['port'] = df_vulns_by_port['port'].astype(str)  # Convertendo para categórico
        fig_vulns_port = px.bar(
            df_vulns_by_port.sort_values(by='n_vulns_in_cisa', ascending=False),
            x='port',
            y=['n_vulns_in_cisa', 'n_vulns_cisa_knownRansomwareCampaignUse'],
            barmode='group',
            labels={'value': '# Vulnerabilities', 'port': 'Port'},
            title='Top 20 Ports by Number of Vulnerabilities (CISA and Known Ransomware)'
        )

        # Gráfico de barra: n_products por porta (Top 20)
        df_products_by_port = df[['port', 'n_products']].copy()
        df_products_by_port = df_products_by_port.groupby('port').sum().reset_index()
        df_products_by_port = df_products_by_port.nlargest(20, 'n_products')
        df_products_by_port['port'] = df_products_by_port['port'].astype(str)  # Convertendo para categórico
        fig_products_port = px.bar(
            df_products_by_port.sort_values(by='n_products', ascending=False),
            x='port',
            y='n_products',
            labels={'n_products': '# Products', 'port': 'Port'},
            title='Top 20 Ports by Number of Products'
        )

        # Lista de produtos por quantidade de portas (Top 10 portas)
        df_products_list = df.explode('product_list')[['port', 'product_list']].copy()
        df_products_list = df_products_list.groupby('product_list')['port'].nunique().reset_index()
        df_products_list = df_products_list.rename(columns={'port': 'n_ports'}).nlargest(10, 'n_ports')
        fig_top_products = px.bar(
            df_products_list.sort_values(by='n_ports', ascending=False),
            x='product_list',
            y='n_ports',
            labels={'product_list': 'Product', 'n_ports': '# Ports'},
            title='Top 10 Products by Number of Ports'
        )

        # Gráfico de erro de CVSS e EPSS (Top 20 portas)
        df_error_metrics = df[['port', 'vulns_cvss_score_max', 'vulns_cvss_score_min', 'vulns_epss_max', 'vulns_epss_min']].copy()
        df_error_metrics['cvss_error'] = df_error_metrics['vulns_cvss_score_max'] - df_error_metrics['vulns_cvss_score_min']
        df_error_metrics['epss_error'] = df_error_metrics['vulns_epss_max'] - df_error_metrics['vulns_epss_min']
        df_error_metrics = df_error_metrics.nlargest(20, ['cvss_error', 'epss_error'])
        df_error_metrics['port'] = df_error_metrics['port'].astype(str)  # Convertendo para categórico
        fig_error_metrics = px.bar(
            df_error_metrics.sort_values(by='cvss_error', ascending=False),
            x='port',
            y=['cvss_error', 'epss_error'],
            barmode='group',
            labels={'value': 'Error', 'port': 'Port'},
            title='Top 20 Ports by Error Metrics (CVSS and EPSS)'
        )

        # Configuração de layout e gráficos
        graphs = [
            dcc.Graph(figure=fig_vulns_port, config={'displayModeBar': False, 'scrollZoom': False}),
            dcc.Graph(figure=fig_products_port, config={'displayModeBar': False, 'scrollZoom': False}),
            dcc.Graph(figure=fig_top_products, config={'displayModeBar': False, 'scrollZoom': False}),
            dcc.Graph(figure=fig_error_metrics, config={'displayModeBar': False, 'scrollZoom': False}),
        ]

        children = gen_subgraphs(n_cols=2, graphs=graphs)
        return children
