import os
from datetime import timedelta

SECRET_KEY = '2!nfin1ty&b3y0nd'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
SQLALCHEMY_TRACK_MODIFICATIONS = False
UPLOAD_FOLDER = '/tmp'
ALLOWED_EXTENSIONS = {'txt'}
PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
