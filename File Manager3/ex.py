if __name__ == '__main__':
    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT version();")
        print("PostgreSQL version:", cur.fetchone())
        cur.close()
        conn.close()
