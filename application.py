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
import stripe
from botocore.client import ClientMeta
from botocore.exceptions import ClientError
from botocore.vendored.six import assertCountEqual
from flask import *
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from paypalcheckoutsdk.core import PayPalHttpClient, SandboxEnvironment
from paypalcheckoutsdk.orders import OrdersCreateRequest
from paypalhttp import HttpError

app = Flask(__name__)
app.secret_key = "secretKey000"

# AWS Keys
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

# Stripe Keys
pk = "pk_test_51HZWy0GvdcoiAyvVMva45A1r74HoaKNxFilbka1JYWZuM0Aa124a9kHyBdi84L7EwUlxnXZ9d8e57LXhlyZOz9zf00XZva9tAf"
stripe.api_key = "sk_test_51HZWy0GvdcoiAyvVu8NzEmoMEA2s8RyR2fpNPeP4DGxOzziuTDvsvmUuwG3YgUhEgPgeqvLnLNLf3QAUXLCq6rpT00pr221LWg"

# PayPal Keys
paypal_client_id = "AWsOkuVbFzlYZeH7oEDr7LiiRR_9NMkEYPraKjf5m8m-SpnmgO-TFhIA53WNnwwvMyWPDO91kWNAbQcT"
paypal_sk = "EB7kT36J2GGfvIk6_5OWsBO-rePeJSkPYmgZG8ZbT38NMfZFhNpWcE5_nTmtpzDa9T7tUIAo-XzqqC3s"
environment = SandboxEnvironment(client_id=paypal_client_id, client_secret=paypal_sk)
client = PayPalHttpClient(environment)

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
    popular = get_popular()
    popular_items = []

    for p in popular:
        split_product = p.split(':', 1)[0]
        product = get_products_by_name(split_product)
        popular_items.append(product)

    return render_template('index.html', popular_items=popular_items, u_session=u_session, product_list=product_list, new=new, popular=popular)

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
                result = loggedIn(username, password, valid, error)
                loggedString = str(result)
                loggedStrip = loggedString.strip("()")
                lsplit = loggedStrip.split(', ')[0]
                cognito_at = loggedStrip.split(', ')[1]
                session['cognito_at'] = cognito_at.strip("'")
                logged = lsplit.strip("'")
                if(logged == "true"):
                    session['user'] = username
                    return redirect(url_for("index"))
                else:
                    errorString = str(result)
                    errorStrip = errorString.strip("()")
                    esplit = errorStrip.split(', ')[1]
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


# Profile
@app.route('/profile')
def profile():
    u_session = check_user_session()
    
    userInfo = getUser()
    
    return render_template('profile.html', u_session=u_session, userInfo=userInfo)


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
    key = pk
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
            session['total'] = total * 100

        if request.method == 'POST':
            if 'remove' in request.form:
                session.pop('bag', None)
                return redirect(url_for('bag', u_session=u_session, error=error))

        return render_template('bag.html', paypal_client_id=paypal_client_id, u_session=u_session, key=key, error=error, total=total, bag=bag, product_list=product_list)
    else:
        error = "Bag is currently empty."
        return render_template('bag.html', u_session=u_session, error=error, total=total)

# Create Stripe session
@app.route('/create-stripe-session', methods=['POST'])
def create_stripe_session():

    total = session.get('total', None)

    stripe_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
        'price_data': {
            'currency': 'aud',
            'product_data': {
            'name': 'Arika',
            },
            'unit_amount': total,
        },
        'quantity': 1,
        }],
        mode='payment',
        success_url='http://127.0.0.1:8080/success_stripe',
        cancel_url='http://127.0.0.1:8080/bag',
    )
    return jsonify({"sessionId": stripe_session["id"]})


# Success page for Stripe
@app.route('/success_stripe')
def success_stripe():
    u_session = check_user_session()
    if 'bag' in session:
        bag = session['bag']
        product_list = []
        for product in bag:
            p_list = product_list
            p_list.append(get_products_by_name(product))
            product_list = p_list
        
        for p in product_list:
            name = p[0]['name']
            popularity = p[0]['popularity'] 
            popularity += 1
            update_popularity(name, popularity)

    session.pop('bag', None)
    session.pop('total', None)
    return render_template('success_stripe.html', u_session=u_session)

# Success page for PayPal
@app.route('/success_paypal')
def success_paypal():
    u_session = check_user_session()
    if 'bag' in session:
        bag = session['bag']
        product_list = []
        for product in bag:
            p_list = product_list
            p_list.append(get_products_by_name(product))
            product_list = p_list
        
        for p in product_list:
            name = p[0]['name']
            popularity = p[0]['popularity'] 
            popularity += 1
            update_popularity(name, popularity)

    session.pop('bag', None)
    session.pop('total', None)
    return render_template('success_paypal.html', u_session=u_session)


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
        response = client.initiate_auth(
            ClientId='7p0cuvbjof3nuvp3ho2hh3srun',
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        
        cognito_access_token = response['AuthenticationResult']['AccessToken']
        valid = "true"
        return valid, cognito_access_token
    except Exception as e:
        ex = str(e)
        error = ex.split(": ",1)[1]
        return valid, error
    

# Get user
def getUser():
    client = boto3.client('cognito-idp', region_name='ap-southeast-2')
    cognito_at = session['cognito_at']

    response = client.get_user(
        AccessToken = cognito_at
    )
    
    attr_list = []
    attr_list.append(response['Username'])
    for attr in response['UserAttributes']:
        if attr["Name"] == "given_name":
            attr_list.append(attr['Value'])
        if attr["Name"] == "family_name":
            attr_list.append(attr['Value'])
        if attr["Name"] == "email":
            attr_list.append(attr['Value'])
        if attr["Name"] == "phone_number":
            attr_list.append(attr['Value'])
        if attr["Name"] == "address":
            attr_list.append(attr['Value'])        
    
    return attr_list


# Products DB =====================================================================================

# Update 'popularity' column in 'product' table
def update_popularity(name, popularity, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2',
                                  aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    table = dynamodb.Table('product')
    response = table.update_item(
        Key={
            'name': name
        },
        UpdateExpression="SET popularity = :p",
        ExpressionAttributeValues={
            ':p': popularity
        }
    )
    return response

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

def get_popular():
    lambda_client = boto3.client('lambda', region_name='ap-southeast-2', 
    aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    result = lambda_client.invoke(FunctionName='get-popular-items-dynamodb', InvocationType='RequestResponse', Payload='{}')

    items = result['Payload'].read()
    return items

# Lambda Functions =================================================================================

# Get popular products from DynamoDB using Lambda
def get_popular():
    lambda_client = boto3.client('lambda', region_name='ap-southeast-2', 
    aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    result = lambda_client.invoke(FunctionName='get-popular-items-dynamodb', InvocationType='RequestResponse', Payload='{}')
    
    items = result['Payload'].read().decode('UTF-8')
    load_items = json.loads(items)
    return load_items

# Run App
if __name__ == "__main__":
    # app.run(host='0.0.0.0', debug=True)
    app.run(debug=True)
