from flask import Flask, request, render_template_string, jsonify
import sqlite3
import os

from init_db import makeDatabase

app = Flask(__name__)

DB_PATH = '/app/database.db'

def create_dbFile():
    if not os.path.exists(DB_PATH):
        open(DB_PATH, 'w').close()  # create an empty file

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            category TEXT,
            price REAL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            flag TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Product Search</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 16px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Product Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search products..." value="{{ query }}">
        <button type="submit">Search</button>
    </form>
    {% if results %}
    <table>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Category</th>
            <th>Price</th>
        </tr>
        {% for product in results %}
        <tr>
            <td>{{ product[0] }}</td>
            <td>{{ product[1] }}</td>
            <td>{{ product[2] }}</td>
            <td>${{ product[3] }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
</body>
</html>
    ''')

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    if not query:
        return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Product Search</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 16px; }
    </style>
</head>
<body>
    <h1>Product Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search products...">
        <button type="submit">Search</button>
    </form>
</body>
</html>
        ''')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    sql = f"SELECT id, name, category, price FROM products WHERE name LIKE '%{query}%'"
    
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
    except Exception as e:
        results = []
    
    conn.close()
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Product Search</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 16px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Product Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search products..." value="{{ query }}">
        <button type="submit">Search</button>
    </form>
    {% if results %}
    <table>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Category</th>
            <th>Price</th>
        </tr>
        {% for product in results %}
        <tr>
            <td>{{ product[0] }}</td>
            <td>{{ product[1] }}</td>
            <td>{{ product[2] }}</td>
            <td>${{ product[3] }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
</body>
</html>
    ''', query=query, results=results)

if __name__ == '__main__':
    create_dbFile()
    init_db()
    makeDatabase()
    app.run(host='0.0.0.0', port=5000)

