import project.query1 as query1
import project.query2 as query2
import project.query3 as query3
import project.query4 as query4
import project.query5 as query5
import project.general as general
import project.auth as auth

def register_callbacks(dm, app):
    auth.register_callback_query(dm, app)
    general.register_callback_query(dm, app)
    query1.register_callback_query(dm, app)
    query2.register_callback_query(dm, app)
    query3.register_callback_query(dm, app)
    query4.register_callback_query(dm, app)
    query5.register_callback_query(dm, app)
