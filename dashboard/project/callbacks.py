import project.query1 as query1
import project.query2_orgs as query2_orgs
import project.query2_ips as query2_ips
import project.query3 as query3
import project.query4 as query4
import project.query5 as query5
import project.query6 as query6
import project.general as general
import project.auth as auth

def register_callbacks(dm, app):
    auth.register_callback_query(dm, app)
    general.register_callback_query(dm, app)
    query1.register_callback_query(dm, app)
    query2_orgs.register_callback_query(dm, app)
    query2_ips.register_callback_query(dm, app)
    query3.register_callback_query(dm, app)
    query4.register_callback_query(dm, app)
    query5.register_callback_query(dm, app)
    query6.register_callback_query(dm, app)