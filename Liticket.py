from flask import Flask, render_template, request, make_response, redirect, jsonify, send_file
from db import SQLiteDatabase
import json
from urllib import parse
import time
import util
from util import hash_password
import uuid
import os
import pkg_resources

def create_app():
    VERSION = pkg_resources.get_distribution('Liticket').version

    app = Flask(__name__)

    db = SQLiteDatabase()

    # List of session tokens.
    tokens = []

    # Set the cookie expiry time to 24 hours.
    COOKIE_EXPIRY = 60 * 60 * 24

    # Function to validate the cookie.
    def validate_token(cookie):
        return cookie in tokens

    @app.before_request
    def before_request():
        """
        Check if the user is authenticated before each request.

        This function is executed before each request and checks if the user is authenticated.
        If the user is not authenticated, it redirects the user to the login page.

        Returns:
            If the user is authenticated, returns None.
            If the user is not authenticated, redirects the user to the login page with a 401 status code.
        """

        # Check if user is trying to login or get the css file.
        if request.endpoint not in ['login', 'css']:
            # Check if the liticket_auth cookie exists
            if 'liticket_auth' in request.cookies:
                # Parse the liticket_auth cookie
                cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))
                # Check if the session token is valid
                if not validate_token(cookie):
                    # Redirect the user to the login page with a 401 status code
                    return redirect('/login', code=401)
            else:
                # Redirect the user to the login page with a 401 status code
                return redirect('/login', code=401)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Handles the login functionality of the application.

        If the request method is 'POST', it checks the provided credentials against the database.
        If the credentials are valid, it redirects the user to the dashboard and sets a cookie to authenticate the user.
        If the credentials are invalid, it renders the login.html template with an error message.

        If the request method is 'GET', it simply renders the login.html template.

        Returns:
            If the request method is 'POST' and the credentials are valid, redirects the user to the dashboard.
            If the request method is 'POST' and the credentials are invalid, renders the login.html template with an error message.
            If the request method is 'GET', renders the login.html template.
        """

        if request.method == 'POST':
            # Get the provided credentials
            username = request.form['username']
            password = request.form['password']
            
            # Check credentials
            user = db.get_user_by_username(username)

            if user is None:
                # Render the login.html template with an error message
                return render_template('login.html', error='Invalid username or password' ,version=VERSION)

            # Get the saved credentials from the database
            db_password = user[2]
            db_salt = user[5]

            # Check if the user exists and the password is correct
            if db_password != hash_password(password.encode(), bytes.fromhex(db_salt)):
                # Render the login.html template with an error message
                return render_template('login.html', error='Invalid username or password', version=VERSION)
            else:
                # Redirect the user to the dashboard and set a cookie to authenticate the user
                response = redirect('/dashboard')
                cookie = {
                    'user_id': user[0],
                    'session_token': uuid.uuid4().hex,
                    'username': user[1],
                    'display_name': user[3],
                    'is_admin': user[4] == 1,
                }
                tokens.append(cookie)
                response.set_cookie('liticket_auth', parse.quote_plus(json.dumps(cookie)), expires=round(time.time() + COOKIE_EXPIRY))
                return response
        else:
            # Render the login.html template
            return render_template('login.html', error=None, title='Login', version=VERSION)

    @app.route('/dashboard', methods=['GET', 'POST'])
    def dashboard():
        """
        Handles the dashboard functionality of the application.

        Retrieves the authenticated user's information from the request cookies.
        Renders the dashboard.html template with the user's information.
        The dashboarad contains quick access to search queries saved by the user.

        Returns:
            The rendered dashboard.html template with the user's information.
        """
        # Retrieve the authenticated user's information from the request cookies
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))

        # Get queries created by this user and public queries
        saved_queries = util.parse_saved_queries(db.get_saved_queries(cookie['user_id'])) + util.parse_saved_queries(db.get_public_queries())

        dashboard_queries = []

        for query in db.get_dashboard_queries(cookie['user_id']):
            queryId = query[1]
            dashboard_queries.append(util.parse_saved_query(db.get_query(queryId)))

        # Store the user's information in a dictionary
        user = {
            'id': cookie['user_id'],
            'username': cookie['username'],
            'display_name': cookie['display_name'],
            'is_admin': db.is_admin(cookie['user_id']),
        }
        if request.method == 'GET':
            # Render the dashboard.html template with the user's information
            return render_template('dashboard.html', current_user=user, saved_queries=saved_queries, dashboard_queries=dashboard_queries, title='Dashboard')
        elif request.method == 'POST':
            # Handle user updating their dashboard saved searches configuration.

            query = request.form.get('add_query')
            if query:
                db.add_dashboard_query(cookie['user_id'], query, len(dashboard_queries))
        
            # Move segment up or down.
            direction = request.form.get('move_segment')
            if direction == 'up':
                segment_id = request.form['segment_id']
                db.move_dashboard_query_up(cookie['user_id'], segment_id)
            elif direction == 'down':
                segment_id = request.form['segment_id']
                db.move_dashboard_query_down(cookie['user_id'], segment_id)

            # Delete segment
            segment_id = request.form.get('delete_segment')
            if segment_id:
                db.delete_dashboard_query(cookie['user_id'], segment_id)

            return redirect('/dashboard')




    @app.route('/search_tickets', methods=['GET'])
    def search_tickets_api():
        """
        Handles the search tickets API functionality of the application.

        Retrieves the query parameter from the request arguments.
        Searches for tickets with the given query using the database.
        Returns a JSON response containing the search results.

        Returns:
            A JSON response containing the search results.
        """
        # Retrieve the query parameter from the request arguments
        query = request.args.get('query')

        # Search for tickets with the given query using the database
        tickets = db.search_tickets(query)

        # Return a JSON response containing the search results
        return make_response(jsonify(tickets))


    @app.route('/search', methods=['GET'])
    def search_api():
        """
        Handles the search API functionality of the application.

        Retrieves the query parameter from the request arguments.
        Builds a SQL query to search for tickets with the given query.
        Renders the search.html template with the query and search results.

        Returns:
            The rendered search.html template.
        """
        # Retrieve the query parameter from the request arguments
        q = request.args.get('query')

        # Build a SQL query to search for tickets with the given query
        query = (
            f"DESCRIPTION LIKE '%{q}%' OR TITLE LIKE '%{q}%'"
            if q else '1=2'
        )

        # Render the search.html template with the query and search results
        return render_template(
            'search.html',  # Template to render
            title='Search',  # Page title
            query={  # Query used for search
                'query': query,
                'name': 'Search results'
            }
        )


    @app.route('/segment', methods=['POST'])
    def segment_api():
        """
        Handles the segment API functionality of the application.

        Retrieves the query parameter from the request JSON.
        Searches for tickets with the given query using the database.
        Renders the segment.html template with the query and search results.

        Returns:
            The rendered segment.html template.
        """
        # Retrieve the query parameter from the request JSON
        query = request.json['query']

        # Search for tickets with the given query using the database
        tickets = util.parse_tickets(db.search_tickets(query['query']))

        # Render the segment.html template with the query and search results
        return render_template(
            'segment.html',  # Template to render
            query=query,    # Query used for search
            tickets=tickets  # Tickets matching the query
        )



    @app.route('/saved_queries', methods=['GET'])
    def saved_queries_api():
        """
        Handles the saved queries API functionality of the application.

        Retrieves the authenticated user's information from the request cookies.
        Retrieves the saved queries for the user from the database.
        Returns a JSON response containing the saved queries.

        Returns:
            A JSON response containing the saved queries.
        """
        # Check if the user is authenticated
        if 'liticket_auth' not in request.cookies:
            return make_response(jsonify([]))

        # Retrieve the authenticated user's information from the request cookies
        user_id = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))['user_id']
        user_data = db.get_user_by_id(user_id)

        # Create a User object with the user's information
        user = {
            'id': user_data[0],
            'username': user_data[1],
            'display_name': user_data[3],
            'is_admin': db.is_admin(user_id),
        }

        # Retrieve the public and user queries from the database
        public_queries = db.get_public_queries()
        user_queries = db.get_saved_queries(user['id'])

        # Combine the public and user queries into a list of dictionaries
        all_queries = []
        for query in public_queries + user_queries:
            all_queries.append({
                'id': query[0],
                'name': query[1],
                'query': query[2],
                'user': query[3],
            })

        # Return a JSON response containing the saved queries
        return make_response(jsonify(all_queries))


    @app.route('/admin', methods=['GET', 'POST'])
    def admin_page():
        """
        Route for the admin page.

        This route handles both GET and POST requests to the '/admin' endpoint.
        Users are only allowed to access this page if they are an admin.
        If a GET request is made, serves the admin page.
        If a POST request is made, it handles update actions.
        """
        # Check if the user is an admin
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))
        if not db.is_admin(cookie['user_id']):
            return redirect('/dashboard')

        # Retrieve the custom field options
        custom_options = util.parse_field_options(db.get_all_field_options())

        if request.method == 'GET':
            # Retrieve the field types, statuses, and queues and render the template
            fields = util.parse_fields(db.get_field_types())
            statuses = util.parse_statuses(db.get_statuses())
            queues = util.parse_queues(db.get_queues())
            users = util.parse_users(db.get_all_users())
            return render_template('admin.html', title='Admin',
                                custom_fields=fields, statuses=statuses,
                                queues=queues, custom_options=custom_options,
                                users=users)

        elif request.method == 'POST':
            # Handle the admin actions based on the form data
            if request.form.get('action') == 'create_queue':
                # Create a new ticket queue
                new_queue = {
                    'id': uuid.uuid4().hex,
                    'name': request.form['queue_name'],
                    'description': request.form['queue_description'],
                    'author': cookie['user_id'] if 'public' not in request.form else None,
                }
                db.add_queue(new_queue)

            elif request.form.get('action') == 'create_status':
                # Create a new ticket status
                new_status = {
                    'id': request.form['status_name'].lower().replace(' ', '_'),
                    'name': request.form['status_name'],
                    'description': request.form['status_description'],
                    'color': request.form['status_color'],
                }
                db.add_status(new_status)

            elif request.form.get('action') == 'create_custom_field':
                # Create a new custom field type
                new_field = {
                    'id': uuid.uuid4().hex,
                    'name': request.form['field_name'],
                    'description': request.form['field_description'],
                    'required': 'required' in request.form,
                    'enum': 'enum' in request.form,
                }
                db.add_field_type(new_field)

            elif request.form.get('action') == 'create_field_option':
                # Create a new field option
                field = util.parse_field(db.get_field_by_id(request.form['field_id']))
                new_option = request.form['option']
                db.add_field_option(field, new_option)

            elif request.form.get('action') == 'delete_queue':
                # Delete a ticket queue
                db.delete_queue(request.form['queue_id'])

            elif request.form.get('action') == 'delete_status':
                # Delete a ticket status
                db.delete_status(request.form['status_id'])

            elif request.form.get('action') == 'delete_custom_field':
                # Delete a custom field
                db.delete_field(request.form['field_id'])

            elif request.form.get('action') == 'delete_field_option':
                # Delete a field option
                for option in custom_options:
                    if option['field'] + ':' + option['value'] == request.form['option']:
                        db.delete_field_option(option['field'], option['value'])

        # Redirect back to the admin page
        return redirect('/admin')


    def generate_ticket():
        """
        Generate a new ticket with default values.
        """
        id = db.next_ticket_id()
        return {
            "title": "Untitled Ticket",
            "description": "Ticket " + id,
            "id": id,
            "queue": "0",
            "owner": None,
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "status": "open",
            "fields": {}
        }

    @app.route('/create_ticket', methods=['POST'])
    def create_ticket():
        """
        Handle the POST request to create a new ticket.

        This function generates a new ticket using the generate_ticket function,
        and then creates an empty field value for each custom field type in the
        database.

        Returns:
            A redirect response to the newly created ticket.
        """
        # Generate a new ticket
        ticket_data = generate_ticket()

        # Add empty field values for each custom field type
        for field in util.parse_fields(db.get_field_types()):
            ticket_data['fields'][field['id']] = ''

        # Create the ticket in the database
        db.create_ticket(ticket_data)

        # Redirect to the newly created ticket
        return redirect('/ticket/' + ticket_data['id'])

    # Filter for time formatting.
    @app.template_filter('ctime')
    def ctime(value):
        return time.ctime(int(value))

    # Filter for converting user IDs to names.
    @app.template_filter('id_to_name')
    def id_to_name(id, else_option='Nobody'):
        result = db.get_user_by_id(id)
        return util.parse_user(result)['display_name'] if result else else_option

    # Filter for checking if an option is selected.
    @app.template_filter('selected_option')
    def selected_option(ticket, option):
        """
        Check if the given option is selected for the given ticket.

        This function retrieves the value of the given option for the given ticket
        from the database and compares it with the option's value. It returns True
        if the values are equal, False otherwise.

        Args:
            ticket (dict): The ticket to check.
            option (dict): The option to check.

        Returns:
            bool: True if the option is selected, False otherwise.
        """
        # Retrieve the value of the given option for the given ticket
        db_result = db.get_ticket_field_value(ticket['id'], option['field'])
        if db_result is None:
            return False
        
        value = db_result[0]

        # Check if the value of the option is equal to the retrieved value
        return option['value'] == value

    @app.route('/ticket/<ticket_id>', methods=['GET', 'POST'])
    def serve_ticket(ticket_id):
        """
        Route for serving a ticket.

        This route handles both GET and POST requests to view and modify a ticket.
        It retrieves the ticket data from the database and renders the 'ticket.html'
        template with the retrieved data. If a POST request is made, it handles the
        ticket modifications based on the form data.

        Args:
            ticket_id (str): The ID of the ticket to serve.

        Returns:
            A redirect response to the ticket page or the 'ticket.html' template.
        """
        # Retrieve the ticket data from the database
        ticket = util.parse_ticket(db.get_ticket(ticket_id))
        
        # Retrieve the user data from the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))

        # Retrieve the field types and their values for the ticket
        all_fields = util.parse_fields(db.get_field_types())
        field_values = util.parse_field_values(db.get_all_ticket_field_values(ticket_id))

        # Retrieve the user data from the database
        user = {
            'id': cookie['user_id'],
            'username': cookie['username'],
            'display_name': cookie['display_name'],
            'is_admin': db.is_admin(cookie['user_id']),
        }

        if request.method == 'GET':
            if ticket is None:
                return 'Ticket not found', 404

            # Retrieve the comments, attachments, history, field options, statuses, users, and queues for the ticket
            comments = util.parse_comments(db.get_comments(ticket_id))
            attachments = util.parse_attachments(db.get_attachments(ticket_id))
            history = util.parse_history_changes(db.get_ticket_history(ticket))
            field_options = util.parse_field_options(db.get_all_field_options())
            all_statuses = util.parse_statuses(db.get_statuses())
            all_users = util.parse_users(db.get_all_users())
            all_queues = util.parse_queues(db.get_queues())

            # Render the 'ticket.html' template with the retrieved data
            return render_template('ticket.html', title=f'Ticket #{ticket_id}', ticket=ticket, comments=comments, attachments=attachments, history=history, all_fields=all_fields, field_options=field_options, field_values=field_values, all_statuses=all_statuses, all_users=all_users, all_queues=all_queues, current_user=user)

        elif request.method == 'POST':
            # Handle delete request
            if 'delete' in request.form:
                db.delete_ticket(ticket_id)
                return redirect('/dashboard')

            # Handle the ticket modifications based on the form data
            changes = {
                'ticket': ticket_id,
                'id': uuid.uuid4().hex,
                'changes': [],
                'timestamp': round(time.time()),
                'author': cookie['user_id'],
            }

            # Check if the title, status, queue, owner, or description have changed
            # ugly!
            if request.form.get('title') and ticket['title'] != request.form['title']:
                db.update_ticket_title(ticket_id, request.form['title'])
                changes['changes'].append({'field': 'title', 'old_value': ticket['title'], 'new_value': request.form['title']})
            if request.form.get('status') and ticket['status'] != request.form['status']:
                db.update_ticket_status(ticket_id, request.form['status'])
                changes['changes'].append({'field': 'status', 'old_value': ticket['status'], 'new_value': request.form['status']})
            if request.form.get('queue') and ticket['queue'] != request.form['queue']:
                db.update_ticket_queue(ticket_id, request.form['queue'])
                changes['changes'].append({'field': 'queue', 'old_value': ticket['queue'], 'new_value': request.form['queue']})
            if 'owner' in request.form and ticket['owner'] != request.form['owner'] and not (ticket['owner'] == None and request.form['owner'] == ''):
                print('Updating owner')
                new_owner = request.form['owner'] if request.form['owner'] != '' else None
                db.update_ticket_owner(ticket_id, new_owner)
                changes['changes'].append({'field': 'owner', 'old_value': ticket['owner'], 'new_value': new_owner})
            if request.form.get('description') and ticket['description'] != request.form['description']:
                db.update_ticket_description(ticket_id, request.form['description'])
                changes['changes'].append({'field': 'description', 'old_value': ticket['description'], 'new_value': request.form['description']})

            # Check if any custom field values have changed
            for field in all_fields:
                if request.form.get('field_' + field['id']) and next((v for v in field_values if v['field'] == field['id']), None) != request.form['field_' + field['id']]:
                    db.update_ticket_field_value(ticket_id, field['id'], request.form['field_' + field['id']])
                    changes['changes'].append({'field': field['id'], 'old_value': next((v for v in field_values if v['field'] == field['id']), {'value': ''})['value'], 'new_value': request.form['field_' + field['id']]})

            # If any changes were made, update the ticket's updated_at field and append the changes to the ticket history
            if len(changes['changes']) > 0:
                db.update_ticket_updated_at(ticket_id)
                db.append_ticket_history(changes)

            # Redirect to the ticket page
            return redirect(f'/ticket/{ticket_id}')

    @app.route('/comment/add/<ticket_id>', methods=['POST'])
    def add_comment(ticket_id):
        """
        Route for adding a comment to a ticket.

        This route handles POST requests to add a comment to a ticket.
        It retrieves the user ID from the session cookie and creates a new comment
        object with the current time as the ID, the content of the comment, the
        current time as the creation time, the user ID as the author, and the
        ticket ID.
        It then adds the comment to the database and redirects to the ticket page.

        Args:
            ticket_id (str): The ID of the ticket to add the comment to.

        Returns:
            A redirect response to the ticket page.
        """
        # Retrieve the user ID from the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))

        # Create a new comment object with the current time as the ID, the content
        # of the comment, the current time as the creation time, the user ID as
        # the author, and the ticket ID
        comment = {
            'id': uuid.uuid4().hex,
            'content': request.form['content'],
            'created_at': round(time.time()),
            'author': cookie['user_id'],
            'ticket': ticket_id
        }

        # Add the comment to the database
        db.add_comment(comment)

        # Redirect to the ticket page
        return redirect(f'/ticket/{ticket_id}')

    @app.route('/comment/get/<ticket_id>', methods=['GET'])
    def get_comment(ticket_id):
        """
        Route for getting comments of a ticket.

        This route handles GET requests to retrieve comments of a ticket.
        It retrieves comments from the database and parses them into a list of
        dictionaries. It then renders the 'comments.html' template with the
        retrieved comments.

        Args:
            ticket_id (str): The ID of the ticket to get comments of.

        Returns:
            The rendered 'comments.html' template with the retrieved comments.
        """
        # Retrieve comments from the database and parse them into a list of dictionaries
        comments = util.parse_comments(db.get_comments(ticket_id))        
        
        # Render the 'comments.html' template with the retrieved comments
        return render_template('comments.html', comments=comments)

    @app.route('/comment/delete/<ticket_id>/<comment_id>', methods=['POST'])
    def delete_comment(ticket_id, comment_id):
        """
        Route for deleting a comment.

        This route handles POST requests to delete a comment.
        It retrieves the user ID from the session cookie and checks if the user is
        the author of the comment. If so, it deletes the comment from the database
        and redirects to the ticket page.

        Args:
            ticket_id (str): The ID of the ticket the comment belongs to.
            comment_id (str): The ID of the comment to delete.

        Returns:
            A redirect response to the ticket page.
        """
        # Retrieve the user ID from the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))

        # Retrieve the comment from the database and parse it into a dictionary
        comment = util.parse_comment(db.get_comment(comment_id))

        # Check if the user is the author of the comment
        if cookie['user_id'] == comment['author']:
            # Delete the comment from the database
            db.delete_comment(comment_id)
            # Redirect to the ticket page
            return redirect(f'/ticket/{ticket_id}')
        
    @app.route('/attachment/add/<ticket_id>', methods=['POST'])
    def add_attachment(ticket_id):
        """
        Route for adding an attachment to a ticket.

        This route handles POST requests to add an attachment to a ticket.
        It retrieves the user ID from the session cookie and creates a new
        attachment object.
        """

        name = request.files['file'].filename
        content = request.files['file'].read()
        mime_type = request.files['file'].content_type

        # Create a new attachment object
        attachment = {
            'id': uuid.uuid4().hex,
            'ticket': ticket_id,
            'name': name,
            'content': content,
            'mime_type': mime_type
        }

        # Add the attachment to the database
        db.add_attachment(attachment)

        # Redirect to the ticket page
        return redirect(f'/ticket/{ticket_id}')

    @app.route('/attachment/delete/<ticket_id>/<attachment_id>', methods=['POST'])
    def delete_attachment(ticket_id, attachment_id):
        """
        Route for deleting an attachment from a ticket.

        This route handles POST requests to delete an attachment from a ticket.
        It retrieves the user ID from the session cookie and checks if the user is
        the author of the attachment. If so, it deletes the attachment from the
        database and redirects to the ticket page.

        Args:
            ticket_id (str): The ID of the ticket the attachment belongs to.
        """

        # Delete the attachment from the database
        db.delete_attachment(attachment_id)

        # Redirect to the ticket page
        return redirect(f'/ticket/{ticket_id}')

    @app.route('/attachment/get/<attachment_id>', methods=['GET'])
    def get_attachment(attachment_id):
        """
        Route for getting an attachment from a ticket.

        This route handles GET requests to retrieve an attachment from a ticket.
        It retrieves the attachment from the database and parses it into a
        dictionary. It then renders the 'attachment.html' template with the
        retrieved attachment.

        Args:
            attachment_id (str): The ID of the attachment to retrieve.
        """

        # Retrieve the attachment from the database
        attachment = util.parse_attachment(db.get_attachment(attachment_id))

        # Send the attachment to the user
        response = make_response(attachment['content'])
        response.headers['Content-Type'] = attachment['mime_type']
        response.headers['Content-Disposition'] = f'attachment; filename={attachment["name"]}'
        return response

    @app.route('/add_query', methods=['POST'])
    def add_query():
        """
        Route for creating a new saved query.
        """

        # Retrieve the user ID from the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))
        user = cookie['user_id']

        # Create a new saved query object
        query = {
            'id': uuid.uuid4().hex,
            'name': request.form['query_name'],
            'query': request.form['query'],
            'user': user if request.form.get('private') == 'on' else None
        }

        # Add the saved query to the database
        db.add_saved_search(query['id'], query['query'], query['name'], query['user'])

        # Redirect to the dashboard
        return redirect('/dashboard')

    def remove_token(cookie):
        """
        Removes the provided cookie from the tokens list
        """

        tokens.remove(cookie)

    @app.route('/logout')
    def logout():
        """
        Route for logging out of the application.
        """

        # Delete the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))
        remove_token(cookie)
        response = make_response(redirect('/login'))
        response.set_cookie('liticket_auth', '', expires=0)

        return response

    @app.route('/create_user', methods=['POST'])
    def create_user():
        """
        Route for creating a new user.
        """

        # Retrieve the user ID from the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))
        user = cookie['user_id']

        # Check if the user is an admin
        if not db.is_admin(user):
            return 'Unauthorized', 401
        
        salt = os.urandom(32)

        userId = request.form['user_id']
        username = request.form['username']
        password = hash_password(request.form['password'].encode(), salt)
        salt_hex = salt.hex()
        display_name = request.form['display_name']
        admin = int(request.form.get('admin') == 'on')
        # Add the user to the database
        db.add_user(userId, username, display_name, password, admin, salt_hex)

        # Redirect to the dashboard
        return redirect('/dashboard')

    @app.route('/change_password', methods=['GET', 'POST'])
    def change_password():
        """
        Route for changing the password of a user.
        """

        # Retrieve the user ID from the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))
        user = cookie['user_id']
        is_admin = db.is_admin(user)

        # Serve the change password page for GET requests
        if request.method == 'GET':
            users = []
            if is_admin:
                users = util.parse_users(db.get_all_users())
            else:
                users = util.parse_users([db.get_user_by_id(user)])

            return render_template('change_password.html', users=users)
        # Handle POST requests for changing the password
        elif request.method == 'POST':
            target = request.form['target']

            # Check if the user is an admin or trying to change their own password
            if not is_admin and target != user:
                return 'Unauthorized', 401

            # Change the password of the user
            salt = os.urandom(32)
            db.change_password(target, hash_password(request.form['password'].encode(), salt), salt.hex())

        # Log out.
        return redirect('/logout')

    @app.route('/delete_user', methods=['POST'])
    def delete_user():
        """
        Route for deleting a user.
        """

        # Retrieve the user ID from the session cookie
        cookie = json.loads(parse.unquote_plus(request.cookies['liticket_auth']))
        user = cookie['user_id']

        # Check if the user is an admin
        if not db.is_admin(user):
            return 'Forbidden', 403

        # Delete the user from the database
        db.delete_user(request.form['target'])

        # Redirect to the dashboard
        return redirect('/admin')

    # Serve CSS
    @app.route('/css')
    def css():
        return send_file('style.css')

    return app