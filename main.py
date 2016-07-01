import json
import logging
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
        "redirect_uri": "{}/oauth_callback".format(os.environ["HEROKU_URL"]),
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


@app.route("/oauth_callback")
def oauth_callback():
    print("callback made", request)
    payload = request.headers
    print("payload", payload)

    return "hi"