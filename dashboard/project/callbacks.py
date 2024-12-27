import project.query1_summary as query1_summary
import project.query2_orgs as query2_orgs
import project.query2_ips as query2_ips
import project.query3_cve as query3_cve
import project.query4_geo as query4_geo
import project.query5_report as query5_report
import project.query6_as as query6_as
import project.query7_ports as query7_ports
import project.general as general
import project.auth as auth

def register_callbacks(dm, app):
    auth.register_callback_query(dm, app)
    general.register_callback_query(dm, app)
    query1_summary.register_callback_query(dm, app)
    query2_orgs.register_callback_query(dm, app)
    query2_ips.register_callback_query(dm, app)
    query3_cve.register_callback_query(dm, app)
    query4_geo.register_callback_query(dm, app)
    query5_report.register_callback_query(dm, app)
    query6_as.register_callback_query(dm, app)
    query7_ports.register_callback_query(dm, app)