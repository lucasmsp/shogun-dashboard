from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
import csv
from dash.dependencies import Output, Input


INPUT_DATA = 'v3'

# precisamos add a lógica de filtrar os elementos e outras interatividades: https://dash.plotly.com/datatable/interactivity
# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: apenas ao clicar ? por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer ?

# constructs the layout for View 3
def register_layout_query(dfs):
    # visualização 3
    q3 = [
        dbc.Row(
            children=[
                html.H1(children="View 3 - More details by CVE", className='wrapper'),
                dbc.Row(
                    # Renders an interactive table component
                    dash_table.DataTable(

                        id='query-3-table',
                        columns=[
                            {"name": i, "id": i} for i in sorted(dfs[INPUT_DATA].columns)
                        ],
                        hidden_columns=['org_list'],
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        page_current=0,
                        page_size=5,
                        style_data={
                            'whiteSpace': 'normal',
                            'height': 'auto',
                            'max-height': '15px', 'min-height': '15px', 'height': '15px'
                        }
                    ),
                    style={'margin-top': '32px'}

                ),
                html.Br(),
                dcc.Graph(
                    id="query-3-graph",
                    config={
                        'displayModeBar': False,
                        'scrollZoom': True
                    }
                ),
                html.Button('Export csv org-list', id='export-button'),
                html.Div(id='output-container')
            ]
        )
    ]

    
    return q3


# updates the query-3-table data based on user interaction
def register_callback_query(app, dfs):
    
    @app.callback(
        Output('query-3-table', "data"),
        Input('query-3-table', "sort_by"),
    )
    def update_table3(sort_by):

        df = dfs[INPUT_DATA]
        df['org_list'] = df['org_list'].str.join(', ')

        if len(sort_by):
            df = df.sort_values(
                [col['column_id'] for col in sort_by],
                ascending=[
                    col['direction'] == 'asc'
                    for col in sort_by
                ],
                inplace=False
            )

        return df.to_dict('records')

    @app.callback(
        Output('output-container', 'children'),
        Input('export-button', 'n_clicks')
    )

    def export_data(n_clicks):
        if n_clicks:
            data = dfs[INPUT_DATA]['org_list'].tolist()

            with open('org_list.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['org_list'])
                for row in data:
                    writer.writerow([row])
                return 'Data exported successfully'
            return ''