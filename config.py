import os
import certifi
from dotenv import load_dotenv
from pymongo import MongoClient
from flask import Flask
from flask_pymongo import PyMongo
app = Flask(__name__)
app.config["MONGO_URI"]="mongodb://localhost:27017/sigma"
mongo = PyMongo(app)

@app.route("/")
def db():
    mongo.db.files.insert_one({"email":1})
    mongo.db.files.insert_one({"username":2})
    mongo.db.files.insert_one({"password":3})
    return  "<p>hello world</p>"
app.run(debug=True)


# ca=certifi.where()

# # Load environment variables from .env file
# load_dotenv()

# MONGO_URI=os.getenv('MONGODB_URI')
# client=MongoClient(MONGO_URI,tlsCAFile=ca)
# for db in client.list_database_names():
#     print(db)


# Retrieve DB credentials from environment
# DB_HOST = os.getenv('DB_HOST')
# DB_PORT = os.getenv('DB_PORT')
# DB_NAME = os.getenv('DB_NAME')
# DB_USER = os.getenv('DB_USER')
# DB_PASSWORD = os.getenv('DB_PASSWORD')

# # Function to connect to the PostgreSQL database
# def get_db_connection():
#     try:
#         conn = psycopg2.connect(
#             host=DB_HOST,
#             port=DB_PORT,
#             dbname=DB_NAME,
#             user=DB_USER,
#             password=DB_PASSWORD
#         )
#         print("Database connection successful")
#         return conn
#     except Exception as e:
#         print("Error connecting to database:", e)
#         return None
