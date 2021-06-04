from botocore.client import ClientMeta
from botocore.vendored.six import assertCountEqual
from flask import Flask, render_template, session, redirect, url_for, request, Blueprint
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
import boto3
import logging
import urllib.request
from pathlib import Path
import botocore
import re

app = Flask(__name__)
app.secret_key = "secretKey000"
aws_access_key_id = "AKIAVQHEZJ6A4MBK2V5K"
aws_secret_access_key = "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"

# Routes ========================================================================================


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


# Working sign up =================================================================================
def signedUp(username, password, gname, fname, email, pnumber, address, valid):
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


# Sending confirmation ============================================================================
def sendConfirmationCode():
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    username = "asoa2"

    client.resend_confirmation_code(
        ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
        Username=username,
    )


# Confirm =========================================================================================
def confirm(username, code):
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')

    client.confirm_sign_up(
        ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
        Username=username,
        ConfirmationCode=code
    )


# Check logged in =================================================================================
def loggedIn(username, password, valid):
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


# Get user ========================================================================================
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
