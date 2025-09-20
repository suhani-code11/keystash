from flask import Blueprint, jsonify
from db.py import get_db_connection # type: ignore

main = Blueprint('main', __name__)

@main.route('/')
def index():
    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT version();")
        version = cur.fetchone()[0]
        cur.close()
        conn.close()
        return jsonify({'PostgreSQL Version': version})
    else:
        return jsonify({'error': 'Database connection failed'}), 500
