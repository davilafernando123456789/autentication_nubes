from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
import random
import string
from pymongo import MongoClient

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://mongodb-container:27017/prueba'  # Reemplaza con la URL de tu contenedor MongoDB
mongo = PyMongo(app)

# Configuración de AWS SES
AWS_ACCESS_KEY = 'AKIA3BPHK632NGAW5TGA'
AWS_SECRET_KEY = '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'
AWS_REGION = 'us-east-2'  # Cambia según la región de AWS SES

def send_verification_code_ses(email, verification_code):
    client = boto3.client('ses', region_name=AWS_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)

    subject = 'Código de Verificación'
    body = f"Tu código de verificación para poder loguearte a la aplicacion de Jose Davila es: {verification_code}"
    
    response = client.send_email(
        Destination={
            'ToAddresses': [email],
        },
        Message={
            'Body': {
                'Text': {
                    'Charset': 'UTF-8',
                    'Data': body,
                },
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': subject,
            },
        },
        Source='josefernandodavila2001@gmail.com',  # Cambia con tu dirección de correo electrónico verificada en SES
    )

@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()

        username, email, phone_number, password, verification_code = (
            data.get('username'),
            data.get('email'),
            data.get('phone_number'),
            data.get('password'),
            data.get('verification_code')
        )

        if not password:
            return jsonify({'error': 'La contraseña es obligatoria'})

        verification_code = ''.join(random.choices(string.digits, k=6))

        user_id = mongo.db.users.insert_one({
            'username': username,
            'password': generate_password_hash(password, method='pbkdf2:sha256'),
            'email': email,
            'phone_number': phone_number,
            'verification_code': verification_code
        }).inserted_id

        # Enviar código de verificación por correo electrónico usando AWS SES
        # send_verification_code_ses(email, verification_code)

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form.to_dict()

        username, password = data.get('username'), data.get('password')

        user = mongo.db.users.find_one({'username': username})

        if user:
            stored_password = user.get('password')
            if stored_password and check_password_hash(stored_password, password):
                verification_code = ''.join(random.choices(string.digits, k=6))
                mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'verification_code': verification_code}})

                # Enviar código de verificación por correo electrónico usando AWS SES
                send_verification_code_ses(user['email'], verification_code)

                return render_template('verification.html', username=username)
            else:
                return render_template('login.html', error='Credenciales incorrectas o contraseña no configurada correctamente')

        return render_template('login.html', error='Credenciales incorrectas o usuario no encontrado')

    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        data = request.form.to_dict()
        username, verification_code = data.get('username'), data.get('verification_code')

        user = mongo.db.users.find_one({'username': username, 'verification_code': verification_code})

        if user:
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'verified': True}})
            return render_template('home.html', username=username)
        else:
            return render_template('verification.html', username=username, error='Código de verificación incorrecto')

    return render_template('verification.html')

@app.route('/logout')
def logout():
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True, port=4200)
