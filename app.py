from flask import Flask, redirect, render_template, request, url_for
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pickle
import pandas as pd
import joblib
# Initialize Flask app
app = Flask(__name__, static_url_path='/static')

# Secret key for encryption (must be 16, 24, or 32 bytes long)
SECRET_KEY = b'\xbe\xe9y\x05\xe3dB3=S#\xc7\xeas(\xd3'

# Load ML model (replace 'model.pkl' with your actual model file)
print("Loading ML model...")
model = joblib.load('model.pkl')
print("ML model loaded successfully.")

# AES encryption function
def encrypt_data(data):
    print("Encrypting data...")
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    print("Data encrypted successfully.")
    return ciphertext, cipher.nonce, tag

# AES decryption function
def decrypt_data(ciphertext, nonce, tag):
    print("Decrypting data...")
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    print("Data decrypted successfully.")
    return decrypted_data.decode().strip()  # Strip extra spaces

# Route for the form
@app.route('/')
def login():
    return render_template('Login.html')

# @app.route('/', methods=['GET','POST'])
# def process_login():    
#     username = request.form['username']
#     password = request.form['password']    
#     if username == 'demo' and password == 'demo':        
#         return redirect(url_for('index_page'))
#     else:    
#         return redirect(url_for('login'))
    
# @app.route('/index.html', methods=['GET', 'POST'])
# def index_page():
#     return render_template('index.html')

@app.route('/index.html', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get form data
        amount = request.form['amount']
        oldbalanceOrg = request.form['oldbalanceOrg']
        newbalanceOrig = request.form['newbalanceOrig']
        oldbalanceDest = request.form['oldbalanceDest']
        newbalanceDest = request.form['newbalanceDest']
        isFlaggedFraud = request.form['isFlaggedFraud']
        
        print("Form data received:")
        print("Amount:", amount)
        print("Old Balance Origin:", oldbalanceOrg)
        print("New Balance Origin:", newbalanceOrig)
        print("Old Balance Destination:", oldbalanceDest)
        print("New Balance Destination:", newbalanceDest)
        print("Is Flagged Fraud:", isFlaggedFraud)
        
        # Encrypt input data
        data = f"{amount},{oldbalanceOrg},{newbalanceOrig},{oldbalanceDest},{newbalanceDest},{isFlaggedFraud}"
        ciphertext, nonce, tag = encrypt_data(data)
        print(f"Ciphertext (hex): {ciphertext.hex()}")
        print(f"Nonce (hex): {nonce.hex()}")
        print(f"Tag (hex):   {tag.hex()}\n")
        
        decrypted_data = decrypt_data(ciphertext, nonce, tag)
        

        # Split decrypted data into separate values
        decrypted_values = decrypted_data.split(',')
        
        # Convert the decrypted values to a DataFrame
        input_df = pd.DataFrame([decrypted_values],
            columns=['amount', 'oldbalanceOrg', 'newbalanceOrig', 'oldbalanceDest', 'newbalanceDest', 'isFlaggedFraud'])
        
        # Make prediction
        prediction = model.predict(input_df)
        print("Prediction:", prediction)
        
      
        return render_template('result.html', prediction=prediction)
    return render_template('index.html')

# @app.route('/result.html', methods=['GET', 'POST'])
# def result():
#     return render_template('result.html')

if __name__ == '__main__':
    app.run(debug=True)
