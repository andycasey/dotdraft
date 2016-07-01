import logging
from flask import Flask, render_template, request

import dotdraft

app = Flask(__name__)

@app.route("/", methods=["GET", ])
def root():
    return render_template("index.html") 

@app.route("/", methods=["POST", ])
def recieve_payload():
    print("Receiving POST payload")

    try:
        result = dotdraft.webhook(request)
   
    except:
        logging.exception("Exception occurred:")

    return "Everything is going to be 200 OK."
