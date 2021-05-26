from app.collection import collectionList
from flask import Flask, render_template, session, redirect, url_for, request, Blueprint
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
import boto3
import json
import logging
import urllib.request
from pathlib import Path
from app.collection import collection

app = Flask(__name__)
app.secret_key = "secretKey000"

# Blueprints
app.register_blueprint(collection)

# Index 
@app.route('/')
def index():
    return render_template('index.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    return render_template('login.html', error=error)

# Sign up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None

    return render_template('signup.html', error=error)

# Run App
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)