from flask import Flask, render_template, request

import dotdraft

app = Flask(__name__)

@app.route("/", methods=["GET", ])
def root():
    return render_template("index.html") 

@app.route("/", methods=["POST", ])
def recieve_payload():
   print("Doing stuff")
   result = dotdraft.webhook(request)
   print("Result is ", result)
   return "Everything is going to be 200 OK."
