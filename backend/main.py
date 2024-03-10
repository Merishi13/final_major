import os
from flask import Flask
from flask_restful import Resource, Api
from application.config import LocalDevelopmentConfig
from application.database import db
from flask_security import Security, SQLAlchemySessionUserDatastore
from flask_cors import CORS, cross_origin
from application.models import User
from flask_caching import Cache

app = None
api=None
celery = None
cache = None

def create_app():
    app = Flask(__name__, template_folder="templates")
    app.secret_key = 'Secret Key'
    if os.getenv('ENV', "development") == "production":
      raise Exception("Currently no production config is setup.")
    else:
      print("Staring Local Development")
      app.config.from_object(LocalDevelopmentConfig)
    db.init_app(app)

    # user_datastore = SQLAlchemySessionUserDatastore(db.session, User,Role)
    
    # security = Security(app, user_datastore)
    # api = Api(app)
    # app.app_context().push()
    
    # CORS(app,allow_headers=["Content-Type"],origins=["http://localhost:8080"], supports_credentials=True,resources={r"/api/*": {"origins": "http://localhost:8080"},r"/login*": {"origins": "http://localhost:8080"}})
    # app.config['CORS_HEADERS'] = 'application/json'
    CORS(app, supports_credentials=True)
    CORS(app, resources={r"/api/*": {"origins": "*", "methods": "GET,POST,PUT,DELETE"}})
    app.config['CORS_HEADERS'] = 'application/json'
    app.app_context().push()
    cache = Cache(app)
    app.app_context().push()
    return app, api, celery, cache

app, api, celery, cache = create_app()

from application.controllers import *

if __name__ == '__main__':
  # Run the Flask app
  app.run(host='0.0.0.0')
