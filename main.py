import json
import logging
import github
import requests
import os
import psycopg2 as pg
import urlparse
from flask import Flask, g, redirect, render_template, request
from urllib import urlencode

import dotdraft

app = Flask(__name__)


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


# ROUTING

@app.route("/")
def root():
    return render_template("index.html") 



#@app.route("/event", methods=["POST"])
@app.route("/", methods=["POST"])
def trigger_event():
    """ A webhook has been triggered from GitHub. """

    database = get_database()

    revision = dotdraft.Revision(request, database)
    if not revision.is_valid or not revision.is_expected:
        logging.info("Not valid or expected.")
        return None

    # OK, we are going to build it!
    try:
        build_identifier = revision.build()

    except:
        # stdout, stderr
        logging.exception("Failed to build")

        revision.set_state("error")

    else:
        # Update the state / add a comment on the commit.
        logging.info("Completed build {}".format(build_identifier))

    database.commit()

    return True


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

    cursor = get_database().cursor()
    cursor.execute(
        "SELECT ip_address, created FROM oauth_states WHERE state = %s",
        (state, ))

    # TODO: Make oauth_tokens expire? Require the same IP address?

    # Do we have this state?
    if cursor.fetchone() is None:
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

        payload = r.json()

        # Need to know who this user is.
        user = github.Github(login_or_token=payload["access_token"]).get_user()
        primary_email_address \
            = [item["email"] for item in user.get_emails() if item["primary"]][0]

        # Create a new user.
        cursor.execute(
            "INSERT INTO users (email, token, scope) VALUES (%s, %s, %s)",
            (primary_email_address, payload["access_token"], payload["scope"]))

        # Delete the state, since we no longer need it.
        cursor.execute("DELETE FROM oauth_states WHERE state = %s", (state, ))

        cursor.close()
        get_database().commit()

        return render_template("oauth_success.html")

    else:
        return (render_template("500.html"), 500)


@app.route("/pdf/<str:basename>")
def retrieve_pdf(basename):
    """
    Serve a stored PDF from the database.

    :param basename:
        A unique basename (e.g., <owner>.<repo>.<issue>.pdf)
    """

    return None