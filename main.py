import logging
import os
import urllib.request
from decimal import Decimal
from pathlib import Path

import boto3
import botocore
import google.auth.transport.requests
import requests
from boto3.compat import filter_python_deprecation_warnings
from boto3.dynamodb.conditions import Attr, Key
from botocore import credentials
from botocore.client import ClientMeta
from botocore.exceptions import ClientError
from botocore.vendored.six import assertCountEqual
from flask import *
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

app = Flask(__name__)
app.secret_key = "secretKey000"
aws_access_key_id = "AKIAVQHEZJ6A4MBK2V5K"
aws_secret_access_key = "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"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

google_client_id = "1032499516768-35kg0d0fbfu1paqgei4tgdb1i76c7kh6.apps.googleusercontent.com"
google_client_secret = os.path.join(Path(__file__).parent, "static/arika_google.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=google_client_secret,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:8080/callback"
                                     )


# Routes ========================================================================================

# Check if user is logged in or not
def check_user_session():
    if 'user' in session:
        return True
    elif 'google_id' in session:
        return True
    else:
        return False

# Index
@app.route('/')
def index():
    u_session = check_user_session()
    product_list = get_products_by_category()
    new = get_new()

    return render_template('index.html', u_session=u_session, product_list=product_list, new=new)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("index"))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    valid = "false"
        
    if "user" in session:
        return redirect(url_for("index"))
    else:
        # get the data from the form
        if request.method == "POST":
            if "login" in request.form:
                username = request.form["username"]
                password = request.form["password"]
                logged = loggedIn(username, password, valid, error)
                if(logged[0:] == "true"):
                    session['user'] = username
                    return redirect(url_for("index"))
                else:
                    errorString = str(logged)
                    stringStrip = errorString.strip("()")
                    esplit = stringStrip.split(', ')[1]
                    error = esplit.strip("'")
                    return render_template('login.html', error=error)
            
            # Google login redirect
            if "google" in request.form:
                authorization_url, state = flow.authorization_url()
                session["state"] = state
                return redirect(authorization_url)
                
        
        return render_template('login.html')


# Google call back
@app.route("/callback")
def gcallback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=google_client_id
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect(url_for("index"))

# Sign up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    valid = "false"
        
    if "user" in session:
        return redirect(url_for("index"))
    else:
        # get the data from the form
        if request.method == "POST":
            username = request.form["username"]
            gname = request.form["gname"]
            fname = request.form["fname"]
            email = request.form["email"]
            pnumber = request.form["pnumber"]
            address = request.form["address"]
            password = request.form["password"]
            logged = signedUp(username, password, gname, fname, email, pnumber, address, valid, error)
            if(logged[0:] == "true"):
                return redirect(url_for("confirm"))
            else:
                errorString = str(logged)
                stringStrip = errorString.strip("()")
                esplit = stringStrip.split(', ')[1]
                error = esplit.strip("'")
                return render_template('signup.html', error=error)


        return render_template('signup.html', error=error)


# Confirm
@app.route('/confirmation', methods=['GET', 'POST'])
def confirm():
    error = None
    valid = "false"

    if "user" in session:
        return redirect(url_for("index"))
    else:
        # get the data from the form
        if request.method == "POST":
            username = request.form["user"]
            code = request.form["code"]
            logged = userConfirm(username, code, valid, error)
            if(logged[0:] == "true"):
                return redirect(url_for("login"))
            else:
                errorString = str(logged)
                stringStrip = errorString.strip("()")
                esplit = stringStrip.split(', ')[1]
                error = esplit.strip("'")
                return render_template('confirm.html', error=error)

        return render_template('confirm.html', error=error)


# Collection category page
@app.route('/collection')
def collectionList():
    u_session = check_user_session()
    error = None
    product_list = get_products_by_category()

    return render_template('collection.html', u_session=u_session, error=error, product_list=product_list)

# Women category page
@app.route('/women')
def women():
    u_session = check_user_session()
    product_list = get_women()
    return render_template('women.html', u_session=u_session, product_list=product_list)

# Men category page
@app.route('/men')
def men():
    u_session = check_user_session()
    product_list = get_men()
    return render_template('men.html', u_session=u_session, product_list=product_list)

# New category page
@app.route('/new')
def new():
    u_session = check_user_session()
    product_list = get_new()
    return render_template('new.html', u_session=u_session, product_list=product_list)

# Individual product page
@app.route('/product/<product_name>', methods=['GET', 'POST'])
def product(product_name):
    u_session = check_user_session()
    message = None
    product_list = get_products_by_name(product_name)

    if request.method == 'POST':
        if 'bag' not in session:
            session['bag'] = []
        bag = session['bag']
        bag.append(request.form['product_name'])
        session['bag'] = bag
        message = "Successfully added to bag!"
        return render_template('product.html', u_session=u_session, message=message, product_name=product_name, product_list=product_list, bag=bag)
    else:
        return render_template('product.html', u_session=u_session, message=message, product_name=product_name, product_list=product_list)

# Bag/cart page
@app.route('/bag', methods=['GET', 'POST'])
def bag():
    u_session = check_user_session()
    error = None
    total = 0

    if 'bag' in session:
        bag = session['bag']
        product_list = []
        for product in bag:
            p_list = product_list
            p_list.append(get_products_by_name(product))
            product_list = p_list

        for p in product_list:
            total += int(p[0]['price'])

        if request.method == 'POST':
            if 'remove' in request.form:
                session.pop('bag', None)
                return redirect(url_for('bag', u_session=u_session, error=error))

        return render_template('bag.html', u_session=u_session, error=error, total=total, bag=bag, product_list=product_list)
    else:
        error = "Bag is currently empty."
        return render_template('bag.html', u_session=u_session, error=error, total=total)


# Signing up =================================================================================
def signedUp(username, password, gname, fname, email, pnumber, address, valid, error):
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
    

# confirmation =========================================================================================
def userConfirm(username, code, valid, error):
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    try:
        client.confirm_sign_up(
            ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
            Username=username,
            ConfirmationCode=code
        )
        valid = "true"
        return valid
    except Exception as e:
        ex = str(e)
        error = ex.split(": ",1)[1]
        return valid, error

# Check logged in =================================================================================
def loggedIn(username, password, valid, error):
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

# Products DB =====================================================================================

# Scan and get products from 'product' table by NAME
def get_products_by_name(name, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2',
                                  aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    table = dynamodb.Table('product')
    response = table.query(
        KeyConditionExpression=Key('name').eq(name)
    )
    return response['Items']

# Scan and get products from 'product' table by CATEGORY
def get_products_by_category(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2',
                                  aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    table = dynamodb.Table('product')
    response = table.scan(
        FilterExpression=Attr('category').eq("Women") | Attr(
            'category').eq("Men") | Attr('category').eq("New")
    )
    return response['Items']

# Scan and get 'Women' products from 'product' table
def get_women(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2', 
        aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    table = dynamodb.Table('product')
    response = table.scan(
        FilterExpression=Attr('category').eq("Women")
    )
    return response['Items']

# Scan and get 'Men' products from 'product' table
def get_men(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2', 
        aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    table = dynamodb.Table('product')
    response = table.scan(
        FilterExpression=Attr('category').eq("Men")
    )
    return response['Items']

# Scan and get 'New' products from 'product' table
def get_new(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2', 
        aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    table = dynamodb.Table('product')
    response = table.scan(
        FilterExpression=Attr('category').eq("New")
    )
    return response['Items']


# Run App
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)
