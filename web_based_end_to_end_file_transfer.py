from flask import Flask, request, render_template_string, redirect, url_for, flash
import pyAesCrypt
import socket
import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flash messages

# Configuration
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Global Variables Initialization
bufferSize = 128 * 1024
chunkSize = 16
port = 2221

def longLine():
    print("--------------------------------------------------------------------------------")

def title():
    print("Dencryptor")
    longLine()

def sendFileScreen(rHost, fileToSendPath, keySize):
    title()
    print("Waiting For Receiver's Confirmation...")
    longLine()

    # Create a random decryption key based on the chosen key size
    decryptionKey = os.urandom(keySize // 8)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    try:
        print(f"Connecting to {rHost}:{port}")
        sock.connect((rHost, port))
        print("Connected to the receiver.")
        sendConfirm = sock.recv(1)
        if sendConfirm.decode('utf-8') == '1':
            encryptedFileName = os.path.basename(fileToSendPath) + ".dnc"
            pyAesCrypt.encryptFile(fileToSendPath, encryptedFileName, decryptionKey.decode('latin1'), bufferSize)
            with sock, open(encryptedFileName, 'rb') as f:
                print("Sending File Name")
                longLine()
                sock.sendall((encryptedFileName + '\n').encode())
                time.sleep(0.3)
                print("Sending File Size")
                longLine()
                sock.sendall(f'{os.path.getsize(encryptedFileName)}\n'.encode())
                time.sleep(0.3)
                print("Generating RSA Key Pair")
                key = RSA.generate(2048)
                private_key = key.export_key()
                public_key = key.publickey().export_key()
                print("Sending Public Key")
                sock.sendall(public_key)
                time.sleep(0.3)
                print("Receiving Receiver's Public Key")
                receiver_public_key = RSA.import_key(sock.recv(2048))
                print("Encrypting Key with Receiver's Public Key")
                cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
                encryptedKey = cipher_rsa.encrypt(decryptionKey)
                print("Sending Encryption Key Size")
                sock.sendall((str(len(encryptedKey)) + '\n').encode())
                time.sleep(0.1)
                print("Sending Encryption Key")
                sock.sendall(encryptedKey)
                time.sleep(0.1)
                print("Secure Key Transfer Complete")
                longLine()
                time.sleep(0.1)
                print("Sending Encrypted File")
                longLine()
                f.seek(0)  # Ensure file pointer is at the beginning
                while True:
                    data = f.read(chunkSize)
                    if not data:
                        break;
                    sock.sendall(data)
                print("File Has Been Sent")
                sock.close()
                flash("File sent successfully", "success")
        else:
            print("Receiver rejected the connection")
            sock.close()
            flash("Receiver rejected the file", "error")
    except socket.timeout:
        print("Connection attempt timed out.")
        flash("Connection attempt timed out.", "error")
    except socket.error as e:
        print(f"Sender: Socket error occurred: {e}")
        sock.close()
        flash(f"Sender: Socket error occurred: {e}", "error")

def receiveFileScreen():
    title()
    print("Waiting For Sender To Connect...")
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print("Your IP address: " + ip_address)
    longLine()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    client, addr = sock.accept()
    try:
        print(str(addr) + " Wants To Send A File...")
        client.send(b'1')
        print("Receiving File Name")
        longLine()
        fileName = client.recv(1024).decode('utf-8').strip()
        print("Receiving File Size")
        longLine()
        fileSize = int(client.recv(1024).decode('utf-8').strip())
        print("Generating RSA Key Pair")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        print("Sending Public Key")
        client.sendall(public_key)
        print("Receiving Sender's Public Key")
        sender_public_key = RSA.import_key(client.recv(2048))
        print("Receiving Encryption Key Size")
        encryptedKeySize = int(client.recv(1024).decode('utf-8').strip())
        print("Receiving Encryption Key")
        encryptedKey = client.recv(encryptedKeySize)
        print(f"Encrypted Key Length: {len(encryptedKey)}")
        print("Decrypting Key")
        cipher_rsa = PKCS1_OAEP.new(key)
        decryptedKey = cipher_rsa.decrypt(encryptedKey)
        print("Decrypted Key:", decryptedKey)
        print("Receiving Encrypted File")
        with open(fileName, 'wb') as f:
            received_size = 0
            while received_size < fileSize:
                data = client.recv(chunkSize)
                if not data:
                    break;
                f.write(data)
                received_size += len(data)
        print("File Has Been Received")
        pyAesCrypt.decryptFile(fileName, fileName[:-4], decryptedKey.decode('latin1'), bufferSize)
        client.close()
        flash("File received successfully", "success")
    except Exception as e:
        print(f"An error occurred: {e}")
        client.close()
        flash(f"An error occurred: {e}", "error")

@app.route('/')
def index():
    return render_template_string('''
        <style>
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                font-family: Arial, sans-serif;
                font-size: 18px;
            }
            .container {
                text-align: center;
                border: 1px solid #ccc;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #f9f9f9;
                font-size: 18px;
            }
            .flashes {
                list-style-type: none;
                padding: 0;
                margin: 0 0 20px 0;
                font-size: 18px;
            }
            .flashes li {
                margin: 5px 0;
                padding: 10px;
                border-radius: 5px;
                font-size: 18px;
            }
            .flashes li.success {
                background-color: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }
            .flashes li.error {
                background-color: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            form {
                margin: 10px 0;
                font-size: 18px;
            }
            label, input, select {
                font-size: 18px;
            }
        </style>
        <div class="container">
            <h1>Web Based End To End Encrypted File Transfer</h1>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <ul class=flashes>
                    {% for category, message in messages %}
                        <li class="{{ category }}">{{ message }}</li>
                    {% endfor %}
                    </ul>
                {% endif %}
            {% endwith %}
            <form action="/sendFile" method="post" enctype="multipart/form-data">
                <label for="rHost">Receiver Host:</label>
                <input type="text" id="rHost" name="rHost" required><br><br>
                <label for="fileToSend">File to Send:</label>
                <input type="file" id="fileToSend" name="fileToSend" required><br><br>
                <label for="keySize">Select Key Size:</label>
                <select id="keySize" name="keySize" required>
                    <option value="128">128 bits</option>
                    <option value="256">256 bits</option>
                    <option value="512">512 bits</option>
                    <option value="1024">1024 bits</option>
                </select><br><br>
                <input type="submit" value="Send File">
            </form>
            <form action="/receiveFile" method="post">
                <input type="submit" value="Receive File">
            </form>
        </div>
    ''')

@app.route('/sendFile', methods=['POST'])
def send_file():
    rHost = request.form['rHost']
    fileToSend = request.files['fileToSend']
    keySize = int(request.form['keySize'])
    filePath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(fileToSend.filename))
    fileToSend.save(filePath)
    sendFileScreen(rHost, filePath, keySize)
    return redirect(url_for('index'))

@app.route('/receiveFile', methods=['POST'])
def receive_file():
    if request.form.get('confirm') == 'yes':
        receiveFileScreen()
        return redirect(url_for('index'))
    elif request.form.get('confirm') == 'no':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', port))
        sock.listen(1)
        client, addr = sock.accept()
        client.send(b'0')
        client.close()
        flash("File transfer rejected", "error")
        return redirect(url_for('index'))
    return render_template_string('''
        <style>
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                font-family: Arial, sans-serif;
                font-size: 18px;
            }
            .container {
                text-align: center;
                border: 1px solid #ccc;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #f9f9f9;
                font-size: 18px;
            }
        </style>
        <div class="container">
            <h1>File Transfer</h1>
            <form action="/receiveFile" method="post">
                <p>A sender wants to send a file. Do you want to receive it?</p>
                <button name="confirm" value="yes">Yes</button>
                <button name="confirm" value="no">No</button>
            </form>
        </div>
    ''')

if __name__ == '__main__':
    app.run(debug=True)