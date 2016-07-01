from flask import Flask, render_template, request

import dotdraft

app = Flask(__name__)

@app.route("/", methods=["GET", ])
def root():
    return render_template("index.html") 

@app.route("/", methods=["POST", ])
def recieve_payload():
   print("Doing stuff")
   if not dotdraft.trigger_payload(request):
       return render_template("index.html")
