import sqlite3
from sqlite3 import Error


def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return conn

def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)

def create_user(conn, user):
    sql = ''' INSERT INTO users(email,public_key)
              VALUES(?,?) '''
    cur = conn.cursor()
    cur.execute(sql, user)
    conn.commit()
    return cur.lastrowid

def select_user_by_email(conn, email):

    cur = conn.cursor()
    cur.execute("SELECT public_key FROM users WHERE email=?", (email,))
    rows = cur.fetchall()
    for row in rows:
        print(row)




if __name__ == '__main__':
    conn = create_connection(r".\sec_email.db")

    sql_create_users_table = """ CREATE TABLE IF NOT EXISTS users (
                                    email text PRIMARY KEY,
                                    public_key text
                                ); """
    if conn is not None:
    # create projects table
        create_table(conn, sql_create_users_table)
        user = ('mayyy2', '15d13sa5dsadsad531asd23sa1d23sad5sdsad2')
        user_id = create_user(conn, user)
        select_user_by_email(conn, "mayyy2")

    else:
        print("Error! cannot create the database connection.")



    
def sign_up(conn, email, public_key):
    conn = create_connection(r".\sec_email.db")
    user = (email, public_key)
    user_id = create_user(conn, user)

def look_up(email):
    conn = create_connection(r".\sec_email.db")
    select_user_by_email(conn, email)     