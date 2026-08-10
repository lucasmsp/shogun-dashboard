from dash import html, dcc
import dash_bootstrap_components as dbc

def register_layout_query(filter_modal={}):
    """
    Register the layout of the guide page.

    Args:
        filter_modal (dict): Filter modal component.
    
    Returns:
        html.Div: Layout of the guide page.
    """
    views_info = [
        {
            "title": "1. EPSS Summary",
            "icon": "fas fa-chart-pie",
            "desc": "Provides an overview of the database by aggregating vulnerabilities according to the EPSS (Exploit Prediction Scoring System) classification into different ranges/ranks of exploitation probability.",
            "possibilities": [
                "Visualize the general distribution of the infrastructure's risk level.",
                "Analyze CDF/PDF curves of cumulative probability by criticality.",
                "Identify criticality ranges that concentrate the largest volume of vulnerabilities (e.g., CVEs, IPs, Organizations, and ASNs)."
            ]
        },
        {
            "title": "2. ORG - Highest Vulnerability per Organization",
            "icon": "fas fa-building",
            "desc": "Groups data by organizations and presents the highest vulnerability score (maximum EPSS) associated with each one.",
            "possibilities": [
                "Identify which companies or institutions under your infrastructure have the most exposed assets.",
                "Classify and prioritize organizations with higher security criticality.",
                "Track the total number of IPs and critical CVEs associated with each organization."
            ]
        },
        {
            "title": "3. IP - Highest Vulnerability per IP",
            "icon": "fas fa-desktop",
            "desc": "Focuses on individual IP addresses, displaying the maximum vulnerability classification (EPSS and CVSS) and the vulnerable products detected on each host.",
            "possibilities": [
                "Identify specific high-risk hosts that require immediate remediation.",
                "Check which operating systems and open ports are most vulnerable per IP address.",
                "Perform quick triage based on the severity of each machine on the network."
            ]
        },
        {
            "title": "4. CVE - Vulnerability Report (CVE)",
            "icon": "fas fa-shield-alt",
            "desc": "Provides a detailed report of each vulnerability (CVE), crossing the theoretical severity (CVSS) with the actual probability of exploitation (EPSS), and highlighting whether it is in the CISA KEV catalog or associated with ransomware.",
            "possibilities": [
                "Filter and prioritize vulnerabilities that are being actively exploited in the 'real world' (CISA KEV Catalog).",
                "Identify critical CVEs linked to active ransomware campaigns.",
                "Analyze the detailed description and weakness classification code (CWE) of each threat."
            ]
        },
        {
            "title": "5. AS - Autonomous System Summary (ASN)",
            "icon": "fas fa-network-wired",
            "desc": "Consolidates exposure data based on Autonomous Systems (ASNs), identifying the most exposed network blocks and whether the networks were seen in active traffic.",
            "possibilities": [
                "Evaluate the security posture of IP blocks managed by specific providers.",
                "Check the correlation of criticalities between legitimate and transit ASNs.",
                "Identify if the ASN has records in mitigation systems."
            ]
        },
        {
            "title": "6. PORT - Vulnerable Ports Summary",
            "icon": "fas fa-ethernet",
            "desc": "Presents aggregated metrics on which network ports concentrate the highest number of vulnerabilities or exposed insecure services.",
            "possibilities": [
                "Map the main entry channels (open ports) most vulnerable in your network.",
                "Identify insecure services running on non-standard ports.",
                "Support firewall rule planning based on the prevalence of critical ports."
            ]
        },
        {
            "title": "7. Geoanalysis",
            "icon": "fas fa-map-marked-alt",
            "desc": "Offers a geospatial visualization (interactive maps of Brazilian states and municipalities) of vulnerabilities and exposed hosts in the database.",
            "possibilities": [
                "Geographically identify regions or municipalities with the highest concentration of compromised assets.",
                "Analyze regional distributions to support localized security policies.",
                "Visualize the spatial correlation between critical physical infrastructures and their level of digital exposure."
            ]
        },
        {
            "title": "8. General Analysis per Record",
            "icon": "fas fa-search",
            "desc": "Robust search engine containing the complete payload and details of each scanned record (Shodan). Displays services, IPs, ports, operating systems, cities, ASNs, and additional metadata.",
            "possibilities": [
                "Perform free searches in the service payload using textual queries.",
                "Filter records by complex combinations (e.g., City + OS + Port).",
                "Access the details page of a specific IP and register/vote on the criticality of the analyses for internal cooperation."
            ]
        }
    ]

    cards_layout = []
    for view in views_info:
        possibilities_list = html.Ul(
            [html.Li(item, style={"fontSize": "14px", "marginBottom": "4px"}) for item in view["possibilities"]],
            style={"paddingLeft": "20px", "marginTop": "8px"}
        )
        
        card = dbc.Col(
            dbc.Card(
                [
                    dbc.CardHeader(
                        html.H4(
                            [
                                html.I(className=f"{view['icon']} me-2", style={"color": "#007bff"}),
                                view["title"]
                            ],
                            style={"fontSize": "18px", "fontWeight": "bold", "margin": "0"}
                        ),
                        style={"backgroundColor": "#f8f9fa", "borderBottom": "1px solid #dee2e6"}
                    ),
                    dbc.CardBody(
                        [
                            html.P(view["desc"], style={"fontSize": "15px", "color": "#495057", "lineHeight": "1.5"}),
                            html.B("Possibilities of Analysis:", style={"fontSize": "14px", "color": "#212529"}),
                            possibilities_list
                        ]
                    )
                ],
                style={"height": "100%", "boxShadow": "0 4px 6px rgba(0,0,0,0.05)", "borderRadius": "8px"}
            ),
            width=12,
            lg=6,
            className="mb-4"
        )
        cards_layout.append(card)

    elements = [
        html.H1(children="Analysis Guide", className='wrapper', style={'textAlign': 'center', 'marginBottom': '10px'}),
        html.P(
            "This guide explains the purpose of each view available on the SHOGUN platform and details the practical cybersecurity analyses you can perform in each section.",
            style={'textAlign': 'center', 'fontSize': '16px', 'color': '#6c757d', 'marginBottom': '30px'}
        ),
        dbc.Container(
            [
                dbc.Row(cards_layout)
            ],
            fluid=True
        )
    ]

    tab_guide_content = dbc.Card(
        dbc.CardBody(html.Div(children=[dbc.Row(children=elements)], className="wrapper")),
        className="mt-3",
        id="tab_guide_content"
    )
    
    return tab_guide_content
