import base64
from flask import Flask, get_flashed_messages, render_template, flash, request, redirect, url_for
import os
from flask import send_file
from cryptography.fernet import Fernet
import hashlib
import uuid
import uuid
from flask_pymongo import PyMongo
from pymongo import MongoClient
import bcrypt
import base64
from bson.objectid import ObjectId
import io
file_id = str(uuid.uuid4())


def generate_key(password):
    return base64.urlsafe_b64encode(password.ljust(32).encode('utf-8'))


app = Flask(__name__, template_folder='templates')

app.secret_key = 'your_secret_key'  # Needed for flashing messages
FILE_STORAGE_PATH = os.path.join(os.getcwd(), 'uploads')
os.makedirs(FILE_STORAGE_PATH, exist_ok=True)
ENCRYPTED_FILE_PATH = 'encrypted'
UPLOADS_PATH = 'uploads'

if not os.path.exists(ENCRYPTED_FILE_PATH):
    os.makedirs(ENCRYPTED_FILE_PATH)
if not os.path.exists(UPLOADS_PATH):
    os.makedirs(UPLOADS_PATH)


def generate_key_from_password(password: str) -> bytes:
    # You could use PBKDF2, SHA256, or another method here
    return Fernet.generate_key()  # For simplicity, we are just generating a key directly



def generate_key_from_password(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)


# Routes for rendering HTML files with Jinja2 templates
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.find_one({"username":username})
        if user:
            if bcrypt.checkpw(password.encode('utf-8'),user['password'].encode('utf-8')):
                  return redirect(url_for('upload'))
            else :
                flash("invalid password")
        else:
            flash("username not found")
        # Dummy check for demonstration (replace with real logic)
        if username == 'admin' and password == 'admin':
            return redirect(url_for('admin'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
          
    #flash('Please enter your credentials.')
    return render_template('FileManager_Login.html')

#@app.route('/register')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert_one({
            "email":email,
            "username":username,
            "password":hashed_pw.decode('utf-8')
        })
        print(f"Email: {email}, Username: {username}, Password: {password}")


        # You can store this data or just redirect
        return redirect(url_for('upload'))

    return render_template('FileManager_register.html')


@app.route('/upload', methods=['GET', 'POST'],endpoint='upload')
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password')
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        key = generate_key(password)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(file.read())
        result = filedb.insert_one({
            "filename": file.filename,
            "data": encrypted_data,
            "password_hash":  hashed_pw.decode('utf-8')
        }) 
        file_id = str(result.inserted_id)
        download_link = url_for('download_link',file_id=file_id, _external=True)
        return render_template('file_uploaded.html', download_link=download_link)

    # Check if upload was successful
        if not file or not password:
            flash("File and password are required.")
            return redirect(request.url)

        file_id = str(uuid.uuid4())
        file_path = os.path.join(FILE_STORAGE_PATH, file_id)
        file.save(file_path)
        
        

        # You can add encryption logic here if needed

        download_link = url_for('download_link', file_id=file_id, _external=True)
        return render_template('file_uploaded.html', download_link=download_link)
    success = request.args.get('success')
    file_id = request.args.get('file_id')
    # # GET request: show the upload form
    return render_template('FileManager_UploadFile.html',success=success,file_id=file_id)
    

@app.route('/admin')
def admin():
    username = 'AdminUser'
    return render_template('admin.html', username=username)

def generate_key_from_password(password):
    import base64, hashlib

    if not password:
        raise ValueError("Password cannot be None or empty.")

    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)


@app.route('/password', methods=['GET', 'POST'])
def password():
    if request.method == 'POST':
        password = request.form.get('password')

        if not password:
            flash('Password is required!')
            return redirect(request.url)

        key = generate_key_from_password(password)
        fernet = Fernet(key)

        uploaded_file_path = os.path.join('uploads', 'uploaded.txt')
        if not os.path.exists(uploaded_file_path):
            flash('No file found to encrypt.')
            return redirect(request.url)

        with open(uploaded_file_path, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)
        encrypted_file_name = f"{uuid.uuid4().hex}.encrypted"

        encrypted_file_path = os.path.join('encrypted', encrypted_file_name)
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        return redirect(url_for('download_link', file_id=encrypted_file_name))

    return render_template('password.html')



@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download_link(file_id):
    if request.method == 'POST':
        password = request.form.get('password')
        encrypted_path = os.path.join(ENCRYPTED_FILE_PATH, file_id)
        file_record = filedb.find_one({"_id": ObjectId(file_id)})
        if not file_record:
            flash("File not found.")
            return redirect(request.url)
        stored_hash = file_record['password_hash'].encode('utf-8')
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            flash("Incorrect password.")
            return redirect(request.url)
        # Log the path to ensure it's correct
        print(f"Looking for encrypted file at: {encrypted_path}")

        key = generate_key(password)
        fernet = Fernet(key)

        try:
            decrypted_data = fernet.decrypt(file_record['data'])

            # Serve decrypted file as a download
            return send_file(
                io.BytesIO(decrypted_data),
                download_name=file_record['filename'],
                as_attachment=True
            )
            # Check if the file exists before attempting to open it
            if not os.path.exists(encrypted_path):
                raise FileNotFoundError(f"Encrypted file '{file_id}' not found.")

            with open(encrypted_path, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = fernet.decrypt(encrypted_data)

            # Save decrypted file temporarily
            temp_path = os.path.join(UPLOADS_PATH, 'decrypted_temp.txt')
            with open(temp_path, 'wb') as temp_file:
                temp_file.write(decrypted_data)

            return send_file(temp_path, as_attachment=True, download_name="your_file.txt")

        except Exception as e:
            print(f"Decryption error: {e}")  # Log error message
            #flash("Incorrect password or corrupted file.")
            return redirect(url_for('download_link', file_id=file_id))

    else:
        return '''
            <div>
                {0}
            </div>
            <form method="post">
                Enter password: <input type="password" name="password">
                <button type="submit">Submit</button>
            </form>
        '''.format("<br>".join(f"<p>{msg}</p>" for msg in get_flashed_messages()))

@app.route('/download/<file_id>')
def download(file_id):
    result = filedb.find_one({"_id": ObjectId(file_id)})
    if not result:
        return "File not found", 404

    return render_template('download.html', file=result)
        
    # Logic to retrieve the file path using file_id
    file_path = os.path.join(FILE_STORAGE_PATH, file_id)

    # Check if file exists before sending it
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

    return render_template('download.html', file_id=file_id)



def encrypt_file(file_path, password):
    # Generate a key from the password
    key = Fernet.generate_key()
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = fernet.encrypt(file_data)
    
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    
    # Return the encrypted file path and the key (to verify later)
    return encrypted_file_path, key


def generate_download_link():
    file_id = str(uuid.uuid4())  # Generate a unique identifier for the file
    download_link = f"http://yourdomain.com/download/{file_id}"
    return file_id, download_link



def decrypt_file(encrypted_file_path, password):
    key = Fernet.generate_key()  # Retrieve the original key (from file or session)
    fernet = Fernet(key)
    
    with open(encrypted_file_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    
    decrypted_data = fernet.decrypt(encrypted_data)
    
    decrypted_file_path = f"{encrypted_file_path}.dec"
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    
    return decrypted_file_path



files_info = {}  # Store file metadata, including the password
# Example entry:
# files_info[file_id] = {'file_path': 'path/to/encrypted/file', 'password': 'password'}
app.config["MONGO_URI"]="mongodb://localhost:27017/sigma"
client = MongoClient("mongodb://localhost:27017/")
db = client["sigma"]
users = db["files"]
filedb = db["filedb"]
mongo = PyMongo(app)

if __name__ == '__main__':
    app.run(debug=True)
