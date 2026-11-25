"""Try to create medvault_test using medvault_user connected to postgres db."""
import psycopg2

# Try connecting as medvault_user to the postgres maintenance database
try:
    conn = psycopg2.connect(
        dbname='postgres',
        user='medvault_user',
        password='localtest123',
        host='localhost',
        port=5432
    )
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname='medvault_test'")
    exists = cur.fetchone()
    if exists:
        print("medvault_test already exists!")
    else:
        cur.execute("CREATE DATABASE medvault_test OWNER medvault_user")
        print("Created medvault_test!")
    conn.close()
except Exception as e:
    print("Failed via postgres db:", e)

# Try connecting to medvault db and running CREATE DATABASE there
try:
    conn2 = psycopg2.connect(
        dbname='medvault',
        user='medvault_user',
        password='localtest123',
        host='localhost',
        port=5432
    )
    conn2.autocommit = True
    cur2 = conn2.cursor()
    cur2.execute("SELECT 1 FROM pg_database WHERE datname='medvault_test'")
    exists2 = cur2.fetchone()
    if exists2:
        print("medvault_test already exists (from medvault conn)!")
    else:
        cur2.execute("CREATE DATABASE medvault_test OWNER medvault_user")
        print("Created medvault_test (from medvault conn)!")
    conn2.close()
except Exception as e:
    print("Failed via medvault db:", e)

# Check if the database was already created
try:
    conn3 = psycopg2.connect(
        dbname='medvault_test',
        user='medvault_user',
        password='localtest123',
        host='localhost',
        port=5432
    )
    print("SUCCESS: Can connect to medvault_test!")
    conn3.close()
except Exception as e:
    print("Cannot connect to medvault_test:", e)
