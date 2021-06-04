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

app = Flask(__name__)
app.secret_key = "secretKey000"

# Blueprints
app.register_blueprint(collection)


# working sign up =================================================================================
def signUp(username, password, gname, fname, email, pnumber, address, valid):
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
        valid = True
        return(valid == True)
    except:
        valid = False


# sending confirmation ============================================================================
def sendConfirmationCode():
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    username = "asoa2"

    client.resend_confirmation_code(
        ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
        Username=username,
    )


# confirm =========================================================================================
def confirm(username, code):
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    client.confirm_sign_up(
        ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
        Username=username,
        ConfirmationCode=code
    )


# login ===========================================================================================
def logIn(username, password, valid):
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
        valid = True
        return(valid == True)
    except:
        valid = False

# get user ========================================================================================


def getUser(access_token):

    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    response = client.get_user(
        AccessToken=access_token
    )

    attr_sub = None
    for attr in response['UserAttributes']:
        if attr['Name'] == 'sub':
            attr_sub = attr['Value']
            break

    print('UserSub', attr_sub)


# Index
@app.route('/')
def index():
    return render_template('index.html')

# Login


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    valid = False

    # get the data from the form
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if(logIn(username, password, valid)):
            return redirect(url_for("index"))
        else:
            error = "Incorrect Username or Password"
            return render_template('login.html', error=error)

    return render_template('login.html')

# Sign up


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    valid = False

    # get the data from the form
    if request.method == "POST":
        username = request.form["username"]
        gname = request.form["gname"]
        fname = request.form["fname"]
        email = request.form["email"]
        pnumber = request.form["pnumber"]
        address = request.form["address"]
        password = request.form["password"]
        print("precheck: ", valid)
        if(signUp(username, password, gname, fname, email, pnumber, address, valid)):
            return redirect(url_for("login"))
        else:
            print("else: ", valid)
            error = "There was an error"
            return render_template('signup.html', error=error)

    return render_template('signup.html', error=error)


# Run App
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)
