''' Provided '''
import sys, SocketServer 
from bottle import route, run, template, redirect, request
import ece568helper

@route('/hello')
def hello():
    print 'hello invoked'
    return "Hello World!"

''' Implement Here '''

login_scope = 'profile'
email_scope = 'email'

@route('/login.html')
def login():
    return ece568helper.get_login_html(_addr, _port, _cid, login_scope, email_scope)

@route('/auth.html')
def auth():
    return ece568helper.get_auth_html(_cid)

import oauth2client
from oauth2client import client
import json
import apiclient
from apiclient.discovery import build
from apiclient import errors
from apiclient.http import MediaFileUpload
import httplib2

SCOPES = [
    #something 1, something 2, something 3,..., something N
    'profile',
    'https://www.googleapis.com/auth/drive.file'
]

@route('/drive.html')
def drive():
    # Initialize client object to use Google api.
    # You need client_secrets.json downloaded and stored
    # in the current working directory 
    flow = ece568helper.get_client_object(_addr, _port, SCOPES)

    if 'access_denied' in request.query_string:
        # user denied access
        return template('drive', result='fail')
    
    if 'code' not in request.query_string:
        # redirect user to Google's OAuth 2.0 server inside this if
        # to avoid endlessly repeating
        auth_uri = flow.step1_get_authorize_url()
        return redirect(auth_uri)

    # handle OAuth 2.0 server response (error or auth code)
    # FormsDict has virtual attributes to access any keyword
    auth_code = request.query.code
    # exchange authorization code for access token
    credentials = flow.step2_exchange(auth_code)
    ece568helper.output_helper('credentials', credentials)

    # apply access token to an Http object
    http_auth = credentials.authorize(httplib2.Http())

    # build service object
    plus_service = build('plus', 'v1', http=http_auth)

    # obtain basic profile info of authenticated user
    people_resource = plus_service.people()
    people_document = people_resource.get(userId='me').execute()
    ece568helper.output_helper('profile', people_document)

    # upload profile file to Google Drive
    media_body = MediaFileUpload(filename='profile.out', 
                                 mimetype='text/plain',
                                 resumable=True)
    body = {
        'title': 'profile.out',
        'description': 'Profile information excluding email address',
        'mimeType': 'text/plain'
    }

    # might want to first handle the request then redirect to another URL that
    # doesn't include response params (like auth code) as per Google documentation
    try:
        drive_service = build('drive', 'v2', http=http_auth)
        drive_service.files().insert(
            body=body,
            media_body=media_body).execute()

        return template('drive', result='success')
    except errors.HttpError, error:
        return template('drive', result='fail: '+str(error)) 


''' Provided '''

try:
    _addr = sys.argv[1]
    _port = sys.argv[2]
    _cid = sys.argv[3]
    run(host=_addr, port=_port, debug=True)
except IndexError:
    print 'Usage: python ece568app.py <IP address> <Port> <Client ID>'
except SocketServer.socket.error:
    print '[Fail] port ' + str(_port) + ' is already in use\n' 

