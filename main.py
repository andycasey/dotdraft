import json
import logging
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

@app.route("/", methods=["GET", ])
def root():
    return render_template("index.html") 


@app.route("/", methods=["POST", ])
def recieve_payload():
    logging.info("Receiving POST payload.")

    try:
        result = dotdraft.webhook(request)
   
    except:
        logging.exception("Exception occurred:")

    return "Everything is going to be 200 OK."



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

    # Do we have this state?
    state = request.args.get("state", None)
    cursor = get_database().cursor()
    cursor.execute(
        "SELECT ip_address, created FROM oauth_states WHERE state = %s",
        (state, ))

    if cursor.fetchone() is None:
        cursor.close()
        return (render_template("403.html"), 403)

    data = {
        "client_id": os.environ["GH_CLIENT_ID"],
        "client_secret": os.environ["GH_CLIENT_SECRET"],
        "code": request.args.get("code"),
    }

    # Send this to GitHub.
    r = requests.post("https://github.com/login/oauth/access_token", data=data)
    if r.status_code == 200:

        # Delete the state, since we no longer need it.
        cursor.execute("DELETE FROM oauth_states WHERE state = %s", (state, ))

        # Create a new user.
        print("response is", r, r.text, r.json, r.__dict__)        

        cursor.close()
        get_database().commit()


    else:
        return (render_template("500.html"), 500)

    return "hi"

