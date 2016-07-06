import json
import logging
import github
import requests
import os
import psycopg2 as pg
import urlparse
from functools import wraps
from urllib import urlencode

from flask import \
    (Flask, g, make_response, redirect, render_template, request, session, url_for)

import dotdraft

app = Flask(__name__)
#app.secret_key = os.urandom(128)
app.secret_key = "my pretty"

def get_database():
    """ Get a database connection for the application, if there is context. """

    database = getattr(g, "_database", None)
    if database is None:
        urlparse.uses_netloc.append("postgres")
        url = urlparse.urlparse(os.environ["DATABASE_URL"])
        database = g._database = pg.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
    return database


@app.teardown_appcontext
def close_connection(exception):
    """
    Close any existing connection to the database.

    :param exception:
        An exception that is triggering the application teardown.
    """

    database = getattr(g, "_database", None)
    if database is not None:
        database.close()

    return None



def authentication_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get("access_token", None)
        if token is not None:
            cursor = get_database().cursor()
            cursor.execute(
                "SELECT id, email FROM users WHERE token = %s", (token, ))
            r = cursor.fetchone()
            cursor.close()

        if token is None and r is None:
            return redirect("/signup")

        # Get the user.
        g.user = github.Github(login_or_token=token).get_user()

        return f(*args, **kwargs)
    return decorated_function


# ROUTING

@app.route("/")
def root():
    return render_template("index.html") 



@app.route("/signup")
def oauth_redirect():
    """
    Redirect users to request GitHub access.

    See https://developer.github.com/v3/oauth/
    """

    # Create a random state and store it in the database.
    state = dotdraft.utils.random_string(1024)
    connection = get_database()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO oauth_states (state, ip_address) VALUES (%s, %s)",
        (state, request.remote_addr))
    cursor.close()
    connection.commit()

    data = {
        "client_id": os.environ["GH_CLIENT_ID"],
        "redirect_uri": "{}/oauth".format(os.environ["HEROKU_URL"]),
        "state": state,
        "scope": " ".join([
            "user:email",       # To match the user's email address with hooks.
            "public_repo",      # To make commit statuses.
            "write:repo_hook"   # To setup the required hooks.
        ])
    }

    url = "https://github.com/login/oauth/authorize?{}".format(urlencode(data))

    logging.info("Redirecting to {}".format(url))

    return redirect(url)



@app.route("/oauth")
def oauth_callback():
    """
    Handle a callback from GitHub when a user has authorized the application.

    See https://developer.github.com/v3/oauth/
    """

    state = request.args.get("state", None)
    if state is None:
        return (render_template("403.html"), 403)

    database = get_database()
    cursor = database.cursor()
    cursor.execute(
        "SELECT ip_address, created FROM oauth_states WHERE state = %s",
        (state, ))

    # TODO: Make oauth_tokens expire? Require the same IP address?

    # Do we have this state?
    if not cursor.rowcount:
        cursor.close()
        return (render_template("403.html"), 403)

    data = {
        "client_id": os.environ["GH_CLIENT_ID"],
        "client_secret": os.environ["GH_CLIENT_SECRET"],
        "code": request.args.get("code"),
    }

    # Send this to GitHub.
    r = requests.post("https://github.com/login/oauth/access_token", data=data,
        headers={"Accept": "application/json"})

    if r.status_code == 200:

        # Redirect to /create
        payload = r.json()
        session["access_token"] = payload["access_token"]

        # Delete the state, since we no longer need it.
        cursor.execute("DELETE FROM oauth_states WHERE state = %s", (state, ))

        cursor.close()
        database.commit()

        return redirect("/oauth/create")

    else:
        cursor.close()
        return (render_template("500.html"), 500)



@app.route("/oauth/create")
@authentication_required
def oauth_create_user():
    """
    Create a user account for `.draft` now that we have a GitHub access token in
    the session.
    """

    database = get_database()
    cursor = database.cursor()

    # Check if this user already exists.
    cursor.execute("SELECT token FROM users WHERE id = %s", (g.user.id, ))

    if not cursor.rowcount:
        # Create a new user.
        cursor.execute(
            "INSERT INTO users (id, email, token) VALUES (%s, %s, %s)",
            (g.user.id, g.user.email, session["access_token"]))

        # Synchronize list of repositories.
        dotdraft.hooks.sync_repositories(g.user, database)

    else:
        # Update token for this user.
        cursor.execute("UPDATE users SET token = %s WHERE id = %s",
            (session["access_token"], g.user.id, ))

    cursor.close()
    database.commit()

    # Redirect to the account area.
    return redirect("/account")



@app.route("/account")
@authentication_required
def account():
    """ Show the main area for users that are logged in. """

    database = get_database()
    cursor = database.cursor()

    cursor.execute(
        "SELECT name, hook_id FROM repos WHERE user_id = %s", (g.user.id, ))
    repositories \
        = [dict(zip(["name", "hook_id"], v)) for v in (cursor.fetchall() or {})]

    return render_template("account.html", user=g.user, repositories=repositories)


@app.route("/account/sync")
@authentication_required
def sync_repositories():
    """ Synchronize the list of repositories from GitHub. """

    database = get_database()
    N = dotdraft.hooks.sync_repositories(g.user, database)

    # Commit the database.
    database.commit()

    # json.dumps(dict(zip(("total", "added", "updated", "deleted"), N)))

    # Redirect to the account area.
    return redirect("/account")

    
@app.route("/account/enable/<repository>")
@authentication_required
def enable(repository):
    """
    Enable `.draft` to run on the given repository.

    :param repository:
        The name of the repository.
    """

    dotdraft.hooks.enable(g.user, repository, get_database())

    # Redirect to the account area.
    return redirect("/account")


@app.route("/account/disable/<repository>")
@authentication_required
def disable(repository):
    """
    Disable `.draft` from running on a given repository.

    :param repository:
        The name of the repository.
    """

    dotdraft.hooks.disable(g.user, repository, get_database())

    # Redirect to the account area.
    return redirect("/account")


@app.route("/", methods=["POST"])
def trigger_event():
    """ A webhook has been triggered from GitHub. """

    database = get_database()

    revision = dotdraft.Revision(request, database)
    if not revision.is_valid or not revision.is_expected:
        logging.info("Not valid or expected.")
        return ("", 200)

    # OK, we are going to build it!
    try:
        build_identifier = revision.build()

    except:
        # stdout, stderr
        logging.exception("Failed to build")

        revision.set_state("error",
            target_url="https://github.com/andycasey/dotdraft/issues/new")

    else:
        # Update the state / add a comment on the commit.
        logging.info("Completed build {}".format(build_identifier))

    database.commit()

    return ("", 200)



@app.route("/pdf/<build_id>.pdf")
def pdf(build_id):
    """
    Serve a stored PDF from the database.

    :param build_id:
        The identifier of the build.
    """

    try:
        build_id = int(build_id)

    except (TypeError, ValueError):
        # Nah mate.
        return (render_template("404.html"), 404)


    cursor = get_database().cursor()
    cursor.execute("SET bytea_output TO escape;")
    cursor.execute("SELECT state, pdf FROM builds WHERE id = %s", (build_id, ))

    if not cursor.rowcount:
        cursor.close()
        return (render_template("404.html"), 404)

    state, binary_pdf = cursor.fetchone()
    cursor.close()

    if state != "success":
        logging.info("State of build {} is {}. Returning 404".format(
            build_id, state))
        return (render_template("404.html"), 404)

    response = make_response(str(binary_pdf))
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] \
        = "inline; filename={}.pdf".format(build_id)

    # TODO: return a more useful PDF name.

    return response





@app.route("/build/<build_id>")
def show_build(build_id):
    """
    Show the state and logs related to a given build.

    :param build_id:
        The identifier of the build.
    """

    try:
        build_id = int(build_id)

    except (TypeError, ValueError):
        return (render_template("404.html"), 404)


    cursor = get_database().cursor()
    cursor.execute("SET bytea_output TO escape;")
    cursor.execute(
        """SELECT state, stdout, stderr FROM builds WHERE id = %s""",
        (build_id, ))

    if not cursor.rowcount:
        cursor.close()
        return (render_template("404.html"), 404)

    state, stdout, stderr = cursor.fetchone()

    return render_template("build.html", build_id=build_id, state=state,
        stdout=stdout, stderr=stderr)
