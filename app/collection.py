from flask import Flask, render_template, session, redirect, url_for, request, Blueprint

collection = Blueprint('collection', __name__)

@collection.route("/collection")
def collectionList():
    return render_template('collection.html')

@collection.route("/women")
def women():
    return render_template('women.html')

@collection.route("/men")
def men():
    return render_template('men.html')