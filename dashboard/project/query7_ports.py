from dash import html, dcc, no_update
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input, State

import plotly.express as px
import dash_ag_grid as dag
import plotly.graph_objects as go
import pandas as pd

from project.auxiliar import gen_subgraphs, gen_columns_def, header_mapping, logging
from project.filters import *

INPUT_DATA = 'ports'


def register_layout_query(filter_modal={}):
    """
    Register the layout for the seventh query (Ports summary).

    Args:
        filter_modal (dict): Filter modal configuration.

    Returns:
        dbc.Card: Layout for the seventh query.
    """

    columns, raw_data = gen_columns_def(['port', 'n_vulns', 'n_products',
                                         'vulns_epss_min', 'vulns_epss_avg', 'vulns_epss_max',
                                         'vulns_cvss_min', 'vulns_cvss_avg', 'vulns_cvss_max',
                                         'n_vulns_cisa', 'n_vulns_cisa_ransomware'
                                         ])

    columns['port']['pinned'] = 'left'

    columns = [
        columns['port'],
        columns['n_vulns'],
        columns['n_products'],
        {
            "headerName": header_mapping['epss_info']['name'],
            "headerTooltip": header_mapping['epss_info']['description'],
            "children": [columns['vulns_epss_min'], columns['vulns_epss_avg'], columns['vulns_epss_max']],
        },
        {
            "headerName": header_mapping['cvss_info']['name'],
            "headerTooltip": header_mapping['cvss_info']['description'],
            "children": [columns['vulns_cvss_min'], columns['vulns_cvss_avg'], columns['vulns_cvss_max']],
        },
        {
            "headerName": header_mapping['cisa_info']['name'],
            "headerTooltip": header_mapping['cisa_info']['description'],
            "children": [columns['n_vulns_cisa'], columns['n_vulns_cisa_ransomware']],
        },
    ]

    aggrid = dag.AgGrid(
        id='query-7-table',
        rowData=raw_data,
        columnDefs=columns,
        defaultColDef={"flex": 1, "filter": True, 'resizable': False},
        columnSize="responsiveSizeToFit",
        columnSizeOptions={"skipHeader": False},
        getRowId="params.data.port",
        dashGridOptions={
            "rowSelection": "single",
            'tooltipInteraction': True,
            'tooltipShowDelay': 10,
            'tooltipHideDelay': 10000,
            "animateRows": False,
        },
        csvExportParams={
            "fileName": "query7_ports.csv",
            "exportedRows": "filteredAndSorted",
        }
    )

    elements = [
        dbc.Row(
            html.Div([
                html.H1(children="View 7 - Vulnerable Ports Summary",
                        className='wrapper', style={'textAlign': 'center'}),
                html.H2(
                    children="This visualization allows the analysis of the distribution ports with vulnerable services.",
                    style={'fontSize': '20px', 'top-padding': '40px', 'bottom-padding': '40px'}
                )
            ])
        ),
        dcc.Loading([aggrid]),
        dbc.Row(
            [
                dbc.Col(
                    html.Small(
                        [
                            html.I(className="fas fa-info-circle me-1", style={"color": "#17a2b8"}),
                            " Tip: Click on any cell under the ",
                            html.Strong("# CVEs"),
                            " column to redirect to the CVEs view (filtered by the CVEs on that port). You can also click on a port in the graph below to redirect to the General analysis per record view (filtered by that port)."
                        ],
                        className="text-muted mt-2"
                    ),
                    width=7,
                    style={"textAlign": "left", "paddingLeft": "15px"}
                ),
                dbc.Col(
                    html.Div(
                        [
                            html.Span(
                                id="query-7-row-count",
                                className="me-3 text-muted align-middle",
                                style={"fontSize": "14px", "fontWeight": "500"}
                            ),
                            dbc.Button(
                                [html.I(className="fas fa-download me-2"), "Export to CSV"],
                                id="btn-export-query7-ports",
                                color="primary",
                                size="sm",
                            )
                        ],
                        className="d-flex align-items-center justify-content-end mt-2"
                    ),
                    width=5
                )
            ],
            justify="between",
            align="center"
        ),
        dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
        dbc.Row([html.Div(id='query-7-graph', children=[])])
    ]

    tab7_content = dbc.Card(
        dbc.CardBody(html.Div(children=[dbc.Row(children=elements)], className="wrapper")),
        className="mt-3",
        id="tab7_content"
    )

    return tab7_content


def register_callback_query(dm, app):
    """
    Register the callbacks for the seventh query (Ports summary).

    Args:
        dm (DataManager): Data manager instance.
        app (dash.Dash): Dash application instance.
    """

    @app.callback(
        Output('query-7-table', "rowData"),
        Input('date-picker-single', 'value')
    )
    def update_table7(date_value):
        logging.info(date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)

        if df.empty:
            return [{}]

        return df.to_dict('records')
    
    @app.callback(
        Output("query-7-graph", "children"),
        [
            Input('date-picker-single', 'value'),
            Input('query-7-table', 'filterModel')
        ]
    )
    def update_vulnerability_charts(date_value, filter_modal):
        logging.info(date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA)

        if df.empty:
            return []

        if filter_modal:
            for col, filter_conf in filter_modal.items():
                try:
                    df = filter_by_model(filter_conf, df, col)
                except Exception as e:
                    logging.error(f"error filter query-7-graph: {e}")

        if df.empty:
            return []

        # Gráfico de barra: n_vulns_cisa por porta (Top 20)
        df_cisa = df[['port', 'n_vulns_cisa']].copy()
        df_cisa = df_cisa.groupby('port').sum().reset_index()
        df_cisa = df_cisa.nlargest(20, 'n_vulns_cisa')
        df_cisa['port'] = df_cisa['port'].astype(str)
        fig_vulns_cisa = px.bar(
            df_cisa.sort_values(by='n_vulns_cisa', ascending=False),
            x='port',
            y='n_vulns_cisa',
            labels={'n_vulns_cisa': '# Vulnerabilities', 'port': 'Port'},
            title='Top 20 Ports by Number of Vulnerabilities (CISA)'
        )

        # Gráfico de barra: n_vulns_cisa_ransomware por porta (Top 20)
        df_known = df[['port', 'n_vulns_cisa_ransomware']].copy()
        df_known = df_known.groupby('port').sum().reset_index()
        df_known = df_known.nlargest(20, 'n_vulns_cisa_ransomware')
        df_known['port'] = df_known['port'].astype(str)
        fig_vulns_known = px.bar(
            df_known.sort_values(by='n_vulns_cisa_ransomware', ascending=False),
            x='port',
            y='n_vulns_cisa_ransomware',
            labels={'n_vulns_cisa_ransomware': '# Vulnerabilities', 'port': 'Port'},
            title='Top 20 Ports by Number of Vulnerabilities (Known Ransomware)'
        )

        # Gráfico de barra: n_products por porta (Top 20)
        df_products_by_port = df[['port', 'n_products']].copy()
        df_products_by_port = df_products_by_port.groupby('port').sum().reset_index()
        df_products_by_port = df_products_by_port.nlargest(20, 'n_products')
        df_products_by_port['port'] = df_products_by_port['port'].astype(str)
        fig_products_port = px.bar(
            df_products_by_port.sort_values(by='n_products', ascending=False),
            x='port',
            y='n_products',
            labels={'n_products': '# Products', 'port': 'Port'},
            title='Top 20 Ports by Number of Products'
        )

        # Gráfico de CVSS (três linhas: avg, min, max)
        df_cvss_std = df[['port', 'vulns_cvss_max', 'vulns_cvss_min']].copy()
        df_cvss_std['cvss_std'] = (df_cvss_std['vulns_cvss_max'] - df_cvss_std['vulns_cvss_min']).abs()
        df_cvss_std = df_cvss_std.groupby('port').agg({
            'cvss_std': 'mean',
            'vulns_cvss_max': 'max',
            'vulns_cvss_min': 'min'
        }).reset_index()
        df_cvss_std = df_cvss_std.sort_values(by='cvss_std', ascending=False)
        df_cvss_std['port'] = df_cvss_std['port'].astype(str)
        
        fig_cvss_std = go.Figure()
        fig_cvss_std.add_trace(go.Scatter(
            x=df_cvss_std['port'],
            y=df_cvss_std['cvss_std'],
            mode='lines',
            name='CVSS Avg',
            line=dict(color='blue')
        ))
        fig_cvss_std.add_trace(go.Scatter(
            x=df_cvss_std['port'],
            y=df_cvss_std['vulns_cvss_min'],
            mode='lines',
            name='CVSS Min',
            line=dict(color='red')
        ))
        fig_cvss_std.add_trace(go.Scatter(
            x=df_cvss_std['port'],
            y=df_cvss_std['vulns_cvss_max'],
            mode='lines',
            name='CVSS Max',
            line=dict(color='green')
        ))
        fig_cvss_std.update_layout(
            title='Ports by CVSS Standard Deviation (Avg, Min, Max)',
            xaxis_title='Port',
            yaxis_title='CVSS Value',
            showlegend=True,
            xaxis=dict(showticklabels=False)  # Remove os rótulos inicialmente
        )

        # Gráfico de EPSS (três linhas: avg, min, max)
        df_epss_std = df[['port', 'vulns_epss_max', 'vulns_epss_min']].copy()
        df_epss_std['epss_std'] = (df_epss_std['vulns_epss_max'] - df_epss_std['vulns_epss_min']).abs()
        df_epss_std = df_epss_std.groupby('port').agg({
            'epss_std': 'mean',
            'vulns_epss_max': 'max',
            'vulns_epss_min': 'min'
        }).reset_index()
        df_epss_std = df_epss_std.sort_values(by='epss_std', ascending=False)
        df_epss_std['port'] = df_epss_std['port'].astype(str)
        
        fig_epss_std = go.Figure()
        fig_epss_std.add_trace(go.Scatter(
            x=df_epss_std['port'],
            y=df_epss_std['epss_std'],
            mode='lines',
            name='EPSS Avg',
            line=dict(color='blue')
        ))
        fig_epss_std.add_trace(go.Scatter(
            x=df_epss_std['port'],
            y=df_epss_std['vulns_epss_min'],
            mode='lines',
            name='EPSS Min',
            line=dict(color='red')
        ))
        fig_epss_std.add_trace(go.Scatter(
            x=df_epss_std['port'],
            y=df_epss_std['vulns_epss_max'],
            mode='lines',
            name='EPSS Max',
            line=dict(color='green')
        ))
        fig_epss_std.update_layout(
            title='Ports by EPSS Standard Deviation (Avg, Min, Max)',
            xaxis_title='Port',
            yaxis_title='EPSS Value',
            showlegend=True,
            xaxis=dict(showticklabels=False)  # Remove os rótulos inicialmente
        )
        # Configuração de layout e gráficos
        graphs = [
            dcc.Graph(figure=fig_vulns_cisa, config={'displayModeBar': False, 'scrollZoom': False}),
            dcc.Graph(figure=fig_vulns_known, config={'displayModeBar': False, 'scrollZoom': False}),
            dcc.Graph(figure=fig_products_port, config={'displayModeBar': False, 'scrollZoom': False}),
            dcc.Graph(figure=fig_cvss_std, config={'displayModeBar': False, 'scrollZoom': False}),
            dcc.Graph(figure=fig_epss_std, config={'displayModeBar': False, 'scrollZoom': False}),
        ]

        children = gen_subgraphs(n_cols=2, graphs=graphs)
        return children

    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output("store-filters", "data", allow_duplicate=True),
        Output('dummy-redirect-q7', 'children', allow_duplicate=True),
        Input("query-7-graph", "clickData"),
        State('date-picker-single', 'value'),
        prevent_initial_call=True,
    )
    def filter_by_graph_point(click_data, date_value):
        # print(f"[INFO] Point clicked: {click_data}, Date: {date_value}")

        if click_data:
            # Obter a porta clicada (eixo x)
            port = click_data["points"][0]["x"]  # O 'x' representa a porta
            print(f"[INFO] Filtering by port: {port}")

            filter_opt = {
                "query-5-ag": {
                    'port': {
                        "filterType": "number",
                        "type": "equals",
                        "filter": port
                    }
                }
            }

            return "/dashboard/report", filter_opt, ""

        return no_update, no_update, no_update

    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Output('dummy-redirect-q7b', 'children', allow_duplicate=True),
        Input("query-7-table", "cellClicked"),
        State('date-picker-single', 'value'),
        prevent_initial_call=True,
    )
    def filter_asn(cell, date_value):
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if cell:
            col_id = cell.get("colId", "")
            if col_id == "n_vulns":
                port_val = None
                if isinstance(cell.get("data"), dict):
                    port_val = cell["data"].get("port")
                if port_val is None and cell.get("rowId") is not None:
                    port_val = cell.get("rowId")

                if port_val is not None:
                    matched = df[df["port"].astype(str) == str(port_val)]
                    if not matched.empty:
                        cve_col = "vulns_cve_list" if "vulns_cve_list" in df.columns else ("cve_list" if "cve_list" in df.columns else "vulns_cve_id")
                        cve_data = matched.iloc[0][cve_col]
                        if hasattr(cve_data, 'tolist'):
                            cve_list = cve_data.tolist()
                        elif isinstance(cve_data, (list, tuple)):
                            cve_list = list(cve_data)
                        else:
                            cve_list = [cve_data]

                        top_50_cves = cve_list[:50]
                        filter_opt = {
                            "query-3-ag": {
                                'vulns_cve_id': {
                                    "filterType": "text",
                                    "operator": "OR",
                                    "conditions": [
                                        {
                                            "filter": cve,
                                            "filterType": "text",
                                            "type": "equals"
                                        } for cve in top_50_cves
                                    ]
                                }
                            }
                        }
                        return "/dashboard/cve", filter_opt, ""
        return no_update, no_update, no_update


    @app.callback(
        Output("query-7-table", "exportDataAsCsv"),
        Input("btn-export-query7-ports", "n_clicks"),
        prevent_initial_call=True
    )
    def export_csv_query7_ports(n_clicks):
        if n_clicks:
            return True
        return False

    @app.callback(
        Output('query-7-row-count', 'children'),
        [
            Input('date-picker-single', 'value'),
            Input('query-7-table', 'filterModel')
        ]
    )
    def update_row_count_7(date_value, filter_modal):
        """
        Callback to display total and filtered row counts for query 7 (ports).
        """
        if not date_value:
            return ""

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return "0 de 0 registros"

        total_rows = len(df.index)

        if filter_modal:
            for col, filter_conf in filter_modal.items():
                try:
                    df = filter_by_model(filter_conf, df, col)
                except Exception:
                    logging.error("error filter row count grid7")

        filtered_rows = len(df.index)

        if filter_modal:
            return f"Exibindo {filtered_rows:,} de {total_rows:,} registros".replace(",", ".")
        else:
            return f"Total: {total_rows:,} registros".replace(",", ".")
