import sqlite3
import os

DB_PATH = '/app/database.db'

def makeDatabase():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT OR REPLACE INTO products (id, name, category, price) VALUES
        (1, 'Laptop', 'Electronics', 999.99),
        (2, 'Mouse', 'Electronics', 29.99),
        (3, 'Keyboard', 'Electronics', 79.99),
        (4, 'Monitor', 'Electronics', 249.99)
    ''')

    cursor.execute('''
        INSERT OR REPLACE INTO secrets (id, flag) VALUES
        (1, 'FLAG{SQHELL_h0p3_Y0u_d1d_it_a_la_mano_sinon_tocard}')
    ''')

    conn.commit()
    conn.close()

