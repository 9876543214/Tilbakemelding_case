#! C:\Program Files\Python312\python.exe

import pymysql.cursors
import pymysql
from flask import *
import bcrypt

app = Flask(__name__)
app.secret_key = 'ecret_key'

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'db': 'case',
    'cursorclass': pymysql.cursors.DictCursor
}

def create_database(config):
    connection = pymysql.connect(
        host=config['host'],
        user=config['user'],
        password=config['password']
    )
    try:
        with connection.cursor() as cursor:
            # Lag database hvis den ikke finnes
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `case`")

            connection.select_db(config['db'])

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(50) NOT NULL,
                    password_hash VARCHAR(100) NOT NULL,
                    salt VARCHAR(100) NOT NULL,
                    email VARCHAR(100) NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS posts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    name VARCHAR(50) NOT NULL,
                    email VARCHAR(100) NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    finally:
        connection.close()

create_database(db_config)

displayerr = False
preverr_home = None
preverr_login = None

def fetch_messages():
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    sql = """
        SELECT * FROM posts ORDER BY created_at DESC
    """
    cursor.execute(sql)
    messages = cursor.fetchall()
    conn.close()
    return messages

@app.route('/')
def home():
    global preverr_home
    global displayerr
    err = request.args.get('err', 0) # Henter err kode, hvis ikke blir err = 0
    
    if displayerr == False: 
        if preverr_home == err:
                preverr_home = None
                return redirect(url_for('home'))# refresher url hvis error allerede er vist, så error ikke blir på skjermen
    else:
        displayerr = False
        preverr_home = err

    if 'user_id' in session and session['user_id'] is not None: # Sjekker om bruker er logget inn
        loggedin = "1"
        name = session['name']
    else:
        loggedin = "0"
        name = None

    messages = fetch_messages()        
    return render_template('index.html', err=err, loggedin=loggedin, name=name, messages=messages)


@app.route('/submit', methods=['POST'])
def submit():    
    global displayerr
    message = request.form.get('message')
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    if 'user_id' not in session or session['user_id'] is None:
        Name = request.form.get('name') # Henter data fra form
        Email = request.form.get('email')
        sql = """
            INSERT INTO posts (content, name, email)
            VALUES (%s, %s, %s)
            """
        cursor.execute(sql, (message, Name, Email, )) # Lagrer data i databasen
        conn.commit()
    elif 'user_id' in session and session['user_id'] is not None:
        Name = session['name']
        Email = session['email']
        user_id = session['user_id']        
        sql = """
            INSERT INTO posts (content, user_id, name, email)
            VALUES (%s, %s, %s, %s)
            """
        cursor.execute(sql, (message, user_id, Name, Email, )) # Lagrer data i databasen
        conn.commit()
    else:
        displayerr = True
        return redirect(url_for('home', err=3)) # Hvis det er en feil, retuneres err 3
    conn.close()

    return redirect(url_for('home'))




@app.route('/signup')
def signup(): # Viser register side
    return render_template('signup.html') 

@app.route('/process-signup', methods=['POST'])
def process_signup():
    print("Processing signup")
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    name = request.form.get('name') # Henter nødvendig data
    email = request.form.get('email')
    password = request.form.get('password')
    password_bytes = password.encode('utf-8')


    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(password_bytes, salt) #Hasher passord for tryggere lagring


    try:
        sql = """
            INSERT INTO users (name, email, password_hash, salt)
            VALUES (%s, %s, %s, %s)
            """
        cursor.execute(sql, (name, email, hashed_password, salt,)) # Lagrer data i databasen
        conn.commit()
        sql = """
        SELECT user_id FROM users WHERE email = %s
        """
        cursor.execute(sql, (email,))
        user_id = cursor.fetchone()
        session['user_id'] = user_id['user_id']
        session['name'] = name
        session['email'] = email

    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()
        return redirect(url_for('signup', err = {e}))
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('home'))


@app.route('/login')
def login_page():
    global preverr_login
    global displayerr
    err = request.args.get('err', 0) # Henter err kode, hvis ikke blir err = 0
    
    if displayerr == False: 
        if preverr_login == err:
                preverr_login = None
                return redirect(url_for('home'))# refresher url hvis error allerede er vist, så error ikke blir på skjermen
    else:
        displayerr = False
        preverr_login = err

    return render_template('login.html', err=err)


@app.route('/login_process', methods=['POST'])
def login_process():
    global displayerr
    email_or_username = request.form.get('email')
    password = request.form.get('password')
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()

    password_bytes = password.encode('utf-8')

    sql = """
    SELECT email, name, user_id, salt, password_hash FROM users WHERE email = %s
    """ 
    cursor.execute(sql, (email_or_username,)) # Sjekker om email finnes i databasen
    result = cursor.fetchone()
    if result == None: # Hvis den ikke fant email, leter den etter navn
        sql = """
        SELECT email, name, user_id, salt, password_hash FROM users WHERE name = %s
        """
        cursor.execute(sql, (email_or_username,))
        result = cursor.fetchone()

    if result == None:
        conn.close()
        return redirect(url_for('login_page', err=1)) # Hvis email eller navn ikke finnes, retuneres err 1
    
    print(result)
    salt = result['salt']
    salt_bytes = salt.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, salt_bytes)# Gjør dette passordet lik som den i databasen
    decoded_hash = hashed_password.decode('utf-8') 
    password = None # Tømmer ikke-hashed passord


    if decoded_hash != result['password_hash']:
        displayerr = True
        return redirect(url_for('login_page', err=2)) # Hvis passord ikke er lik den i databasen, retuneres err 2
    else:
        session['user_id'] = result['user_id']
        session['name'] = result['name']
        session['email'] = result['email']
    conn.close()
    return redirect(url_for('home'))

@app.route('/validate_email')
def validate_email():
    email = request.args.get('email')
    conn = pymysql.connect(**db_config) 
    cursor = conn.cursor()

    sql = """
    SELECT email FROM users WHERE email = %s
    """
    cursor.execute(sql, (email,))
    result = cursor.fetchone()

    conn.close()

    print(result)

    if result != None:
        print("Email exists")
        return jsonify({"exists": True, "email": result[0]})
    else:
        print("Email does not exist")
        return jsonify({"exists": False})



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('name', None)
    session.pop('email', None)
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)