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
import os


# working sign up ==========================================================
def signUp(username, password, gname, fname, email, pnumber, address):
  client=boto3.client('cognito-idp', region_name='ap-southeast-2')
  response = client.sign_up(
    ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
    Username = username,
    Password = password,
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
  
  error = response
  print(error)
  




# client = boto3.client('cognito-idp', region_name='ap-southeast-2')
# response = client.initiate_auth(
#   ClientId='4q71sqn47vscmmncoahtgrhbvr',
#   AuthFlow='USER_PASSWORD_AUTH',
#   AuthParameters={
#     'USERNAME': username,
#     'PASSWORD': password
      
#   }
# )

# print(response)

# print('AccessToken', response['AuthenticationResult']['AccessToken'])
# print('RefreshToken', response['AuthenticationResult']['RefreshToken'])




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
  
    # get the data from the form
    if request.method == "POST":
        username = request.form["username"]
        gname = request.form["gname"]
        fname = request.form["fname"]
        email = request.form["email"]
        pnumber = request.form["pnumber"]
        address = request.form["address"]
        password = request.form["password"]
        signUp(username, password, gname, fname, email, pnumber, address)
        return redirect(url_for("login"))

    return render_template('signup.html', error=error)

# Run App
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)