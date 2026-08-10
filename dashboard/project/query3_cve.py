import itertools

import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output, State, no_update
import dash_ag_grid as dag
import plotly.express as px
import plotly.figure_factory as ff

from project.auxiliar import gen_subgraphs, header_mapping, gen_columns_def, logging

import pandas as pd

INPUT_DATA = 'vulns'

def register_layout_query(filter_modal={}):
    """
    Register the layout for the third query (list of vulnerable products for each CVE).

    Args:
        filter_modal (dict): Filter modal configuration.

    Returns:
        dbc.Card: Layout for the third query.
    """
    special_configs = {
        'vulns_cve_id': {
            'maxNumConditions': 500,
            'tooltipValueGetter': {"function": "'Click on the cell for more details'"},
            'pinned': 'left',
            'cellRenderer': 'GoToMitre'
        },
        'vulns_cvss': {
            'tooltipValueGetter': {"function": "'CVSS Version: ' + params.data.vulns_cvss_version"},
        },
        'vulns_epss': {
            'tooltipValueGetter': {"function": "'EPSS: ' + params.data.vulns_epss_rank"},
        },
        'vulns_cwe': {
            'tooltipValueGetter': {"function": "'Click on the cell for more details'"},
            'cellRenderer': "GoToCWE"
        },

        'vulns_cisa_ransomware': {'minWidth': 160, 'cellStyle': {'textAlign': 'center'} },
        'vulns_cisa_product_vendor': {
            'minWidth': 500,
            'tooltipValueGetter': {"function":
                                       "params.data.vulns_cisa_description == '-' ? '' : params.data.vulns_cisa_description"}
        },


    }


    columns, raw_data = gen_columns_def(['vulns_cve_id', 'vulns_cvss', 'vulns_epss', 'vulns_cwe',
                                         'n_as', 'n_ips', 'n_orgs', 'n_port', 'vulns_cisa_date_added',
                                         'vulns_cisa_ransomware', 'vulns_cisa_product_vendor',
                                         'vulns_cvss_version', 'vulns_epss_rank',
                                         'vulns_cisa_description'], special_configs=special_configs)

    columns = list(columns.values())
    columns = columns[:8] + [{
        "headerName": header_mapping['cisa_info']['name'],
        "headerTooltip": header_mapping['cisa_info']['description'],
        "children": columns[8:11],
    }]

    aggrid = dag.AgGrid(
        id="query-3-ag",
        rowData=raw_data,
        columnDefs=columns,
        defaultColDef={"flex": 1, "filter": True, 'resizable': False},
        columnSize="sizeToFit",
        filterModel=filter_modal,
        columnSizeOptions={"skipHeader": False},
        dashGridOptions={
            'tooltipInteraction': True,
            'tooltipShowDelay': 10,
            'tooltipHideDelay': 10000
        },
        csvExportParams={
            "fileName": "query3_cve.csv",
            "exportedRows": "filteredAndSorted",
        }
    )

    elements = [
        dbc.Row(
            html.Div([
                html.H1(children="View 3 - Report of Common Vulnerabilities and Exposures (CVE)",
                        className='wrapper', style={'textAlign': 'center'}),
                html.H2(
                    children="This visualization allows the analysis of the distribution of CVEs "
                             "in relation to IPs and organizations accessible on the Internet.",
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
                            html.Strong("# IPs"),
                            " or ",
                            html.Strong("# Orgs"),
                            " columns to redirect to the IPs view, filtered by that CVE or its exposing organizations."
                        ],
                        className="text-muted mt-2"
                    ),
                    width=9,
                    style={"textAlign": "left", "paddingLeft": "15px"}
                ),
                dbc.Col(
                    dbc.Button(
                        [html.I(className="fas fa-download me-2"), "Export to CSV"],
                        id="btn-export-query3-cve",
                        color="primary",
                        size="sm",
                        className="mt-2",
                        style={"float": "right"}
                    ),
                    width=3
                )
            ],
            justify="between",
            align="center"
        ),
        dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
        dbc.Row([html.Div(id='query-3-graph', children=[])])
    ]

    tab3_content = dbc.Card(
        dbc.CardBody(html.Div(children=[dbc.Row(children=elements)], className="wrapper")),
        className="mt-3",
        id="tab3_content"
    )

    return tab3_content


def find_expression(string):
    list_expressions = ['>=', '<=', '!=']
    for i in list_expressions:
        index = string.find(i)

        if index != -1:
            return i


def register_callback_query(dm, app):
    """
    Register the callbacks for the third query (list of vulnerable products for each CVE).

    Args:
        dm (DataManager): Data manager instance.
        app (dash.Dash): Dash application instance.
    """

    @app.callback(
        Output('query-3-ag', "rowData"),
        Input('date-picker-single', 'value')
    )
    def update_table3(date_value):
        if not date_value:
            return []

        logging.info(date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return []

        df_exploded = df.explode('vulns_cwe')

        df_exploded['vulns_cisa_ransomware'] = df_exploded[
            'vulns_cisa_ransomware'].apply(
            lambda x: (x == 'Known' and '✅') or
                      (x == 'Unknown' and '❌') or '➖')

        df_exploded['vulns_cisa_product_vendor'] = df_exploded[['vulns_cisa_vendor', 'vulns_cisa_product']] \
            .fillna('').agg('/'.join, axis=1)

        df_exploded['vulns_cisa_product_vendor'] = df_exploded['vulns_cisa_product_vendor'].apply(
            lambda x: "" if x == '-/-' else x)

        df_exploded['vulns_cisa_date_added'] = df_exploded['vulns_cisa_date_added'].apply(
            lambda x: "" if x == '-' else x)

        return df_exploded.to_dict('records')

    # TODO: Atualizar gráficos para usar o filtermodal
    @app.callback(
        Output('query-3-graph', "children"),
        Input('date-picker-single', 'value')
    )
    def update_graphs(date_value):
        if not date_value:
            return []

        logging.info(date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)

        if df.empty:
            return []

        graphs = []

        # fig 1
        fig = px.scatter(df, x=df["vulns_cvss"], y=df['vulns_epss'],
                         title="Scatter plot - EPSS by CVSS score",
                         color='vulns_epss_rank')
        fig.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="EPSS",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 2, 4, 6, 8, 10],
                range=[0, 10]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 2
        tmp1 = df.groupby(["vulns_cvss_rank", "vulns_epss_rank"]).count() \
            .reset_index() \
            .pivot(index="vulns_cvss_rank", columns="vulns_epss_rank", values=["vulns_cve_id"]) \
            .fillna(0) \
            .reset_index()
        tmp1.columns = ['vulns_epss_rank', '< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']

        severity_mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        tmp1['severity'] = tmp1['vulns_epss_rank'].map(severity_mapping)
        tmp1 = tmp1.sort_values(by='severity', ascending=True)

        x = ["low", "medium", "high", "critical"]
        y = ['< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']
        tmp1 = tmp1[y].T.values.tolist()
        z_text = [[str(y) for y in x] for x in tmp1]

        fig = ff.create_annotated_heatmap(tmp1, x=x, y=y, annotation_text=z_text, colorscale='Viridis')
        fig['data'][0]['showscale'] = True

        fig.update_layout(
            title_text='Confusion Matrix - EPSS Rank by CVSS Rank',
            xaxis_title="CVSS Rank",
            yaxis_title="EPSS Rank",
            xaxis={'side': 'bottom'},
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 3
        tmp2 = df.groupby("vulns_cvss", as_index=False)["n_ips"].sum()
        fig = px.line(tmp2, x=tmp2['vulns_cvss'], y=tmp2['n_ips'], title="Line plot - # IPs by CVSS")
        fig.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="# IPs",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 2, 4, 6, 8, 10],
                range=[0, 10]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 4
        tmp3 = df.groupby("vulns_cvss", as_index=False)["n_orgs"].sum()
        fig = px.line(tmp3, x=tmp3['vulns_cvss'], y=tmp3['n_orgs'], title="Line plot - # Organizations by CVSS")
        fig.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="# Organizations",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 2, 4, 6, 8, 10],
                range=[0, 10]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 5
        tmp4 = df.groupby("vulns_epss", as_index=False)["n_orgs"].sum()
        fig = px.line(tmp4, x=tmp4['vulns_epss'], y=tmp4['n_orgs'], title="Line plot - # Organizations by EPSS")
        fig.update_layout(
            xaxis_title="EPSS score (%)",
            yaxis_title="# Organizations",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                range=[0, 1.0]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 6
        tmp5 = df.groupby("vulns_epss", as_index=False)["n_ips"].sum()
        fig = px.line(tmp5, x=tmp5['vulns_epss'], y=tmp5['n_ips'], title="Line plot - # IPs by EPSS")
        fig.update_layout(
            xaxis_title="EPSS score (%)",
            yaxis_title="# IPs",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                range=[0, 1.0]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 7
        tmp6 = df.assign(names=df.vulns_cwe.str.split(",")).explode('vulns_cwe')
        tmp6 = tmp6.loc[~tmp6['vulns_cwe'].isin(["NVD-CWE-noinfo", "NVD-CWE-Other"])]
        tmp6 = tmp6.groupby('vulns_cwe', as_index=False)['n_ips'].sum()
        final_df = tmp6.sort_values(by=['n_ips'], ascending=False)
        final_df = final_df[0:25]

        fig = px.bar(final_df, x='vulns_cwe', y='n_ips', title="Bar char - # IP's by CWE", color="n_ips",
                     color_continuous_scale=px.colors.sequential.Viridis)
        fig.update_layout(
            xaxis_title="CWE",
            yaxis_title="# IP's",
            title_x=0.5,
            coloraxis_colorbar=dict(
                title=dict(text="")),
        )

        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 8
        tmp8 = df[["vulns_epss_rank", "vulns_cisa_ransomware", "vulns_cvss"]].copy()
        tmp8["Unknown"] = tmp8["vulns_cisa_ransomware"].apply(lambda x: 1 if x == "Known" else 0)
        tmp8["Known"] = tmp8["vulns_cisa_ransomware"].apply(lambda x: 1 if x == "Unknown" else 0)

        tmp8_aux1 = tmp8.groupby('vulns_epss_rank', as_index=False)['vulns_cvss'].mean()
        tmp8_aux2 = tmp8.groupby("vulns_epss_rank", as_index=False)[["Known", "Unknown"]].sum()

        tmp8_aux1['vulns_cvss'] = tmp8_aux1['vulns_cvss'].apply(lambda x: '{:,.2f}'.format(x))
        tmp8_final = pd.merge(tmp8_aux1, tmp8_aux2, how='left', on="vulns_epss_rank")

        fig = px.bar(tmp8_final, x="vulns_epss_rank", y=["Known", "Unknown"],
                     title="Bar char - # Ransowares by EPSS rank",
                     hover_data={"vulns_cvss": True},
                     labels={'vulns_cvss': 'CVSS Avg'},
                     )
        fig.update_layout(
            xaxis_title="EPSS Rank",
            yaxis_title="# Campaigns",
            title_x=0.5,
            legend_title_text=""
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 9
        tmp9 = df.assign(names=df.vulns_cwe.str.split(",")).explode('vulns_cwe')
        tmp9 = tmp9.loc[~tmp9['vulns_cwe'].isin(["NVD-CWE-noinfo", "NVD-CWE-Other"])]
        tmp9 = tmp9.groupby("vulns_cwe")["vulns_cve_id"].count().reset_index()
        tmp9 = tmp9.sort_values(by=['vulns_cve_id'], ascending=False)[0:25]

        fig = px.bar(tmp9, x="vulns_cwe", y="vulns_cve_id",
                     title="Bar char - Number of CVEs by CWE",
                     labels={'vulns_cve_id': 'Number of CVEs'},
                     color="vulns_cve_id",
                     color_continuous_scale=px.colors.sequential.Viridis
                     )
        fig.update_layout(
            xaxis_title="CWE",
            yaxis_title="Number of CVEs",
            title_x=0.5,
            legend_title_text="",
            coloraxis_colorbar=dict(
                title=dict(text="")),
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        children = gen_subgraphs(n_cols=3, graphs=graphs)
        return children

    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-3-ag", "cellClicked"),
        Input("query-3-ag", "selectedRows"),
        State('date-picker-single', 'value'),
        prevent_initial_call=True
    )
    def select_ips(cell, row, date_value):

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if cell:
            if cell.get("colId", "") == "n_ips":
                row_id = int(cell.get("rowId", 0))
                cve = df.at[row_id, "vulns_cve_id"]
                filter_opt = {
                    "query-2a-grid": {'vulns_cve_id': {'filterType': 'text', 'type': 'contains', 'filter': cve}}}
                return "/dashboard/ips", filter_opt

        return no_update, no_update

    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-3-ag", "cellClicked"),
        State('date-picker-single', 'value'),
        prevent_initial_call=True,
    )
    def select_orgs(cell, date_value):

        df_q2 = dm.get_view_dataset(date_value, 'orgs')
        # TODO: Não esta filtrando todos os elementos da lista, no maximo 2, e existem
        if cell:
            if cell.get("colId", "") == "n_orgs":
                row_id = int(cell.get("rowId", 0))
                cve_value = df_q2.at[row_id, "vulns_cve_id"]
                org_list = df_q2.loc[df_q2["vulns_cve_id"] == cve_value, "org_clean"].drop_duplicates()

                filter_opt = {
                    "query-2a-grid": {
                        'org_clean': {
                            "filterType": "text",
                            "operator": "OR",
                            "conditions": [
                                {
                                    "filter": org,
                                    "filterType": "text",
                                    "type": "equals"
                                } for org in org_list.tolist()[0:50]
                            ]
                        }
                    }
                }
                return "/dashboard/ips", filter_opt
        return no_update, no_update


    @app.callback(
        Output("query-3-ag", "exportDataAsCsv"),
        Input("btn-export-query3-cve", "n_clicks"),
        prevent_initial_call=True
    )
    def export_csv_query3_cve(n_clicks):
        """
        Callback to export the grid data to a CSV file.

        Args:
            n_clicks (int): Number of clicks on the export button.

        Returns:
            bool: True if the export was successful, False otherwise.
        """
        if n_clicks:
            return True
        return False
