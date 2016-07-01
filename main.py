import json
import logging
import requests
import os
from flask import Flask, redirect, render_template, request
from urllib import urlencode

import dotdraft

app = Flask(__name__)


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

    data = {
        "client_id": os.environ["GH_CLIENT_ID"],
        "redirect_uri": "{}/oauth".format(os.environ["HEROKU_URL"]),
        "state": "not-for-production",
        "scope": " ".join([
            "public_repo",
            "write:repo_hook"
        ])
    }

    url = "https://github.com/login/oauth/authorize?{}".format(urlencode(data))

    print(data)
    logging.info("Redirecting to {}".format(url))

    return redirect(url)


@app.route("/oauth")
def oauth_callback():
    """
    Handle a callback from GitHub when a user has authorized the application.
    """

    assert request.args.get("state") == "not-for-production"

    print("request.args", request.args)

    # Check the state is as expected (from the db...)

    data = {
        "client_id": os.environ["GH_CLIENT_ID"],
        "client_secret": os.environ["GH_CLIENT_SECRET"],
        "code": request.args.get("code"),
        "redirect_uri": "{}/oauth/access".format(os.environ["HEROKU_URL"]),
        "state": "not-for-production"
    }

    # Send this to GitHub.
    response = requests.post("https://github.com/login/oauth/access_token",
        data=data)
    print("response is", response, response.text)

    return "hi"


@app.route("/oauth/access")
def oauth_access():
    print("we has access", request)
    return "hi there"