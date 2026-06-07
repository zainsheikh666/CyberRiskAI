from flask import Flask, render_template, request, jsonify
import requests
import socket
import ssl
import datetime
import json

app = Flask(__name__)

# ============================================================
# DOMAIN SCANNER
# ============================================================

def check_ssl(domain):
    try:
        domain = domain.replace('https://','').replace('http://','').replace('www.','').strip()
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expire_date - datetime.datetime.now()).days
        conn.close()
        return {
            'status': 'valid',
            'days_left': days_left,
            'expires': expire_date.strftime('%d %b %Y')
        }
    except Exception as e:
        return {'status': 'invalid', 'days_left': 0, 'expires': 'Unknown'}

def check_dns(domain):
    try:
        domain = domain.replace('https://','').replace('http://','').replace('www.','').strip()
        import dns.resolver
        results = {}

        # SPF Check
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_found = False
            for r in answers:
                if 'v=spf1' in str(r):
                    spf_found = True
            results['spf'] = 'found' if spf_found else 'missing'
        except:
            results['spf'] = 'missing'

        # DMARC Check
        try:
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            results['dmarc'] = 'found'
        except:
            results['dmarc'] = 'missing'

        # MX Check
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            results['mx'] = 'found'
        except:
            results['mx'] = 'missing'

        return results
    except:
        return {'spf': 'unknown', 'dmarc': 'unknown', 'mx': 'unknown'}

def check_breach(email):
    try:
        headers = {'User-Agent': 'CyberRiskAI-Scanner'}
        response = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers=headers,
            timeout=5
        )
        if response.status_code == 200:
            breaches = response.json()
            return {
                'breached': True,
                'count': len(breaches),
                'breaches': [b['Name'] for b in breaches[:3]]
            }
        elif response.status_code == 404:
            return {'breached': False, 'count': 0, 'breaches': []}
        else:
            return {'breached': False, 'count': 0, 'breaches': [], 'error': 'API limit'}
    except:
        return {'breached': False, 'count': 0, 'breaches': [], 'error': 'Could not check'}

def calculate_risk(answers, ssl_result, dns_result, breach_result):
    score = 0
    breakdown = []

    # Question based scoring
    if answers['antivirus'] == 'no':
        score += 18
        breakdown.append({'category': 'Endpoint Security', 'issue': 'No antivirus', 'points': 18, 'severity': 'high'})
    if answers['mfa'] == 'no':
        score += 20
        breakdown.append({'category': 'Access Control', 'issue': 'No MFA enabled', 'points': 20, 'severity': 'high'})
    if answers['backups'] == 'no':
        score += 15
        breakdown.append({'category': 'Data Protection', 'issue': 'No backups', 'points': 15, 'severity': 'high'})
    if answers['training'] == 'no':
        score += 12
        breakdown.append({'category': 'Human Risk', 'issue': 'No security training', 'points': 12, 'severity': 'medium'})
    if answers['passwords'] == 'no':
        score += 12
        breakdown.append({'category': 'Access Control', 'issue': 'Weak passwords', 'points': 12, 'severity': 'medium'})
    if answers['encryption'] == 'no':
        score += 10
        breakdown.append({'category': 'Data Protection', 'issue': 'No encryption', 'points': 10, 'severity': 'medium'})

    # SSL scoring
    if ssl_result['status'] == 'invalid':
        score += 10
        breakdown.append({'category': 'Web Security', 'issue': 'Invalid SSL certificate', 'points': 10, 'severity': 'high'})
    elif ssl_result['days_left'] < 30:
        score += 5
        breakdown.append({'category': 'Web Security', 'issue': f"SSL expires in {ssl_result['days_left']} days", 'points': 5, 'severity': 'medium'})

    # DNS scoring
    if dns_result.get('spf') == 'missing':
        score += 5
        breakdown.append({'category': 'Email Security', 'issue': 'SPF record missing', 'points': 5, 'severity': 'medium'})
    if dns_result.get('dmarc') == 'missing':
        score += 5
        breakdown.append({'category': 'Email Security', 'issue': 'DMARC record missing', 'points': 5, 'severity': 'medium'})

    # Breach scoring
    if breach_result.get('breached'):
        score += 8
        breakdown.append({'category': 'Dark Web', 'issue': f"Found in {breach_result['count']} data breaches", 'points': 8, 'severity': 'high'})

    score = min(score, 100)

    if score >= 60:
        risk_level = 'High'
        risk_message = 'Immediate action required. Your business is highly vulnerable.'
    elif score >= 30:
        risk_level = 'Medium'
        risk_message = 'Some improvements needed. Address the gaps below.'
    else:
        risk_level = 'Low'
        risk_message = 'Good job! Keep maintaining these security practices.'

    return score, risk_level, risk_message, breakdown

def generate_recommendations(answers, ssl_result, dns_result, breach_result):
    recs = []

    if answers['mfa'] == 'no':
        recs.append({'type': 'danger', 'icon': '🚨', 'category': 'Critical', 'text': 'Enable Multi-Factor Authentication immediately — this single step blocks 99% of automated attacks on your accounts.'})
    if answers['antivirus'] == 'no':
        recs.append({'type': 'danger', 'icon': '🚨', 'category': 'Critical', 'text': 'Install antivirus on all devices — Malwarebytes or Windows Defender are free and highly effective.'})
    if answers['backups'] == 'no':
        recs.append({'type': 'danger', 'icon': '🚨', 'category': 'Critical', 'text': 'Set up automated daily backups — ransomware attacks can destroy your data permanently without backups.'})
    if ssl_result['status'] == 'invalid':
        recs.append({'type': 'danger', 'icon': '🔒', 'category': 'Web Security', 'text': 'Your SSL certificate is invalid or missing — customers data is NOT encrypted on your website. Fix this immediately.'})
    elif ssl_result['days_left'] < 30:
        recs.append({'type': 'warning', 'icon': '⚠️', 'category': 'Web Security', 'text': f"Your SSL certificate expires in {ssl_result['days_left']} days — renew it before it expires to avoid website downtime."})
    if dns_result.get('spf') == 'missing':
        recs.append({'type': 'warning', 'icon': '📧', 'category': 'Email Security', 'text': 'SPF record is missing — attackers can send emails pretending to be your company. Add an SPF record to your DNS.'})
    if dns_result.get('dmarc') == 'missing':
        recs.append({'type': 'warning', 'icon': '📧', 'category': 'Email Security', 'text': 'DMARC record is missing — your email domain is vulnerable to spoofing attacks. Add DMARC to protect your brand.'})
    if breach_result.get('breached'):
        recs.append({'type': 'danger', 'icon': '🌑', 'category': 'Dark Web', 'text': f"Your email was found in {breach_result['count']} data breaches. Change all passwords immediately and enable MFA on all accounts."})
    if answers['training'] == 'no':
        recs.append({'type': 'warning', 'icon': '👥', 'category': 'Staff Training', 'text': 'Schedule cybersecurity awareness training — 90% of breaches start with a phishing email clicked by an untrained employee.'})
    if answers['passwords'] == 'no':
        recs.append({'type': 'warning', 'icon': '🔑', 'category': 'Passwords', 'text': 'Enforce strong password policies — use Bitwarden (free) to generate and store unique passwords for every account.'})
    if answers['encryption'] == 'no':
        recs.append({'type': 'warning', 'icon': '🛡️', 'category': 'Encryption', 'text': 'Enable encryption on all devices — BitLocker on Windows and FileVault on Mac are free and built-in.'})

    if not recs:
        recs.append({'type': 'success', 'icon': '✅', 'category': 'All Clear', 'text': 'Excellent security posture! Your business has strong cybersecurity practices in place. Schedule quarterly reviews.'})

    return recs

# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/assessment')
def assessment():
    return render_template('assessment.html')

@app.route('/results', methods=['POST'])
def results():
    company_name = request.form.get('company_name', 'Your Company')
    industry = request.form.get('industry', '')
    employees = request.form.get('employees', '')
    domain = request.form.get('domain', '').strip()
    email = request.form.get('email', '').strip()

    answers = {
        'antivirus': request.form.get('antivirus', 'no'),
        'mfa': request.form.get('mfa', 'no'),
        'backups': request.form.get('backups', 'no'),
        'training': request.form.get('training', 'no'),
        'passwords': request.form.get('passwords', 'no'),
        'encryption': request.form.get('encryption', 'no'),
    }

    # Run scans
    ssl_result = check_ssl(domain) if domain else {'status': 'not_checked', 'days_left': 0, 'expires': 'N/A'}
    dns_result = check_dns(domain) if domain else {'spf': 'not_checked', 'dmarc': 'not_checked', 'mx': 'not_checked'}
    breach_result = check_breach(email) if email else {'breached': False, 'count': 0, 'breaches': []}

    score, risk_level, risk_message, breakdown = calculate_risk(answers, ssl_result, dns_result, breach_result)
    recommendations = generate_recommendations(answers, ssl_result, dns_result, breach_result)

    return render_template('results.html',
        company_name=company_name,
        industry=industry,
        employees=employees,
        domain=domain,
        score=score,
        risk_level=risk_level,
        risk_message=risk_message,
        breakdown=breakdown,
        recommendations=recommendations,
        answers=answers,
        ssl_result=ssl_result,
        dns_result=dns_result,
        breach_result=breach_result
    )

if __name__ == '__main__':
    app.run(debug=True)