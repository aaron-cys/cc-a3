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

aws_access_key_id = "AKIAVQHEZJ6A4MBK2V5K"
aws_secret_access_key = "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"

# Blueprints
app.register_blueprint(collection)

# Index 
@app.route('/')
def index():
    product_list = get_products()

    return render_template('index.html', product_list=product_list)

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

# Scan and get products from 'product' table
def get_products(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2',
        aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    table = dynamodb.Table('product')
    response = table.scan(
        FilterExpression=Attr('category').eq("Women") | Attr('category').eq("Men") | Attr('category').eq("New")
    )
    return response['Items']

# Run App
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)