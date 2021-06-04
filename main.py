from os import execlp
from botocore.client import ClientMeta
from botocore.vendored.six import assertCountEqual
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
import botocore
import re

app = Flask(__name__)
app.secret_key = "secretKey000"

# Blueprints
app.register_blueprint(collection)


# working sign up =================================================================================
def signUp(username, password, gname, fname, email, pnumber, address, valid, error):
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    try:
        client.sign_up(
            ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'given_name',
                    'Value': gname
                },
                {
                    'Name': 'family_name',
                    'Value': fname
                },
                {
                    'Name': 'email',
                    'Value': email
                },
                {
                    'Name': 'phone_number',
                    'Value': pnumber
                },
                {
                    'Name': 'address',
                    'Value': address
                }
            ]
        )
        valid = "true"
        return valid
    except Exception as e:
        ex= str(e)
        error = ex.split(": ",1)[1]
        return valid, error
        
        
        
# login ===========================================================================================
def logIn(username, password, valid, error):
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    try:
        client.initiate_auth(
            ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        valid = "true"
        return valid
    except Exception as e:
        ex = str(e)
        error = ex.split(": ",1)[1]
        return valid, error


# Index
@app.route('/')
def index():
    return render_template('index.html')

# Login


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    valid = "false"

    # get the data from the form
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        logged = logIn(username, password, valid, error)
        if(logged[0:] == "true"):
            return redirect(url_for("index"))
        else:
            errorString = str(logged)
            stringStrip = errorString.strip("()")
            esplit = stringStrip.split(', ')[1]
            error = esplit.strip("'")
            return render_template('login.html', error=error)

    return render_template('login.html')

# Sign up


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    valid = "false"

    # get the data from the form
    if request.method == "POST":
        username = request.form["username"]
        gname = request.form["gname"]
        fname = request.form["fname"]
        email = request.form["email"]
        pnumber = request.form["pnumber"]
        address = request.form["address"]
        password = request.form["password"]
        logged = signUp(username, password, gname, fname, email, pnumber, address, valid, error)
        if(logged[0:] == "true"):
            return redirect(url_for("login"))
        else:
            errorString = str(logged)
            stringStrip = errorString.strip("()")
            esplit = stringStrip.split(', ')[1]
            error = esplit.strip("'")
            return render_template('signup.html', error=error)

    return render_template('signup.html', error=error)


# Run App
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)
