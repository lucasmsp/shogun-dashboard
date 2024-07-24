import project.query1 as query1
import project.query2 as query2
import project.query3 as query3
import project.query4 as query4
import project.general as general

from dash import Input, Output, callback_context

def register_callbacks(dm, app):
    general.register_callback_query(dm, app)
    query1.register_callback_query(dm, app)
    query2.register_callback_query(dm, app)
    query3.register_callback_query(dm, app)
    query4.register_callback_query(dm, app)

    @app.callback(
        Output('url-redirect', 'href'),
        [Input('logout-menu-item', 'n_clicks'), 
        Input('admin-menu-item', 'n_clicks'),
        Input('profile-menu-item', 'n_clicks')],
        prevent_initial_call=True
    )
    def handle_redirect(logout_clicks, admin_clicks, profile_clicks):
        ctx = callback_context

        if not ctx.triggered:
            return None

        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if triggered_id == 'logout-menu-item' and logout_clicks:
            return "/logout"
        elif triggered_id == 'admin-menu-item' and admin_clicks:
            return "/admin"
        elif triggered_id == 'profile-menu-item' and profile_clicks:
            return "/profile"
        
        return None
