from dash import html, dcc
import dash_bootstrap_components as dbc


def gen_subgraphs(n_cols, graphs):
    children = []
    row = []
    size = int(12 / n_cols)
    for i, graph in enumerate(graphs):
        mod_ = i % n_cols
        if (mod_ == 0) and (i != 0):
            children.append(dbc.Row(row, align="start", justify="center"))
            row = []
        row.append(dbc.Col(graph, width={'size': size, 'order': mod_ + 1}))

    if len(row) > 0:
        children.append(dbc.Row(row, align="start", justify="center"))

    return children


header_mapping = {
    'epss_rank': {
        'name': 'EPSS rank',
        "description": "EPSS rank vary from 0 (0%) to 1 (100%)"
    },
    'n_cves': {
            'name': '# CVEs',
            "description": "Number of distinct vulnerabilities"
    },
    'n_ips': {
            'name': '# IPs',
            "description": "Number of IP addresses"
    },
    'n_orgs': {
        'name': '# Organizations',
        "description": "Number of organizations"
    },

}