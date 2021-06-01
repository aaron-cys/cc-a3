from flask import Flask, render_template, session, redirect, url_for, request, Blueprint
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
import boto3
import json
import logging
import urllib.request
from pathlib import Path

collection = Blueprint('collection', __name__)

aws_access_key_id = "AKIAVQHEZJ6A4MBK2V5K"
aws_secret_access_key = "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"

# Collection category page
@collection.route("/collection")
def collectionList():
    error = None
    product_list = get_products()

    return render_template('collection.html', error=error, product_list=product_list)

# Women category page
@collection.route("/women")
def women():
    product_list = get_women()
    return render_template('women.html', product_list=product_list)

# Men category page
@collection.route("/men")
def men():
    product_list = get_men()
    return render_template('men.html', product_list=product_list)

# New category page
@collection.route("/new")
def new():
    product_list = get_new()
    return render_template('new.html', product_list=product_list)

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