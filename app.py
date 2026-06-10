from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
load_dotenv()
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, Company, Assessment
from pdf_generator import generate_pdf_report
import requests
import socket
import ssl
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyberrisk-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberrisk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Company.query.get(int(user_id))

with app.app_context():
    db.create_all()

def validate_domain(domain):
    try:
        domain = domain.replace('https://','').replace('http://','').replace('www.','').strip()
        if not domain or len(domain) < 4:
            return False
        socket.gethostbyname(domain)
        return True
    except:
        return False

def check_ports(domain):
    common_ports = {
        80: ('HTTP', 'medium'),
        443: ('HTTPS', 'low'),
        22: ('SSH', 'medium'),
        21: ('FTP', 'high'),
        3389: ('RDP', 'high'),
        25: ('SMTP', 'medium'),
        3306: ('MySQL', 'high'),
        8080: ('HTTP-Alt', 'medium'),
        445: ('SMB', 'high'),
        1433: ('MSSQL', 'high'),
        27017: ('MongoDB', 'high'),
        6379: ('Redis', 'high'),
    }
    open_ports = []
    closed_ports = []
    domain_clean = domain.replace('https://','').replace('http://','').replace('www.','').strip()
    try:
        ip = socket.gethostbyname(domain_clean)
    except:
        return {'found': False, 'ports': [], 'closed': [], 'ip': None, 'total': 0}
    for port, (service, risk) in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append({'port': port, 'service': service, 'risk': risk, 'status': 'open'})
            else:
                closed_ports.append({'port': port, 'service': service, 'status': 'closed'})
        except:
            pass
    return {'found': True, 'ports': open_ports, 'closed': closed_ports, 'ip': ip, 'total': len(open_ports)}

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
        return {'status': 'valid', 'days_left': days_left, 'expires': expire_date.strftime('%d %b %Y')}
    except:
        return {'status': 'invalid', 'days_left': 0, 'expires': 'Unknown'}

def check_dns(domain):
    try:
        import dns.resolver
        domain = domain.replace('https://','').replace('http://','').replace('www.','').strip()
        results = {}
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            results['spf'] = 'found' if any('v=spf1' in str(r) for r in answers) else 'missing'
        except:
            results['spf'] = 'missing'
        try:
            dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            results['dmarc'] = 'found'
        except:
            results['dmarc'] = 'missing'
        return results
    except:
        return {'spf': 'unknown', 'dmarc': 'unknown'}

def check_breach(email):
    try:
        headers = {'User-Agent': 'CyberRiskAI-Scanner'}
        response = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers=headers, timeout=5)
        if response.status_code == 200:
            breaches = response.json()
            return {'breached': True, 'count': len(breaches), 'breaches': [b['Name'] for b in breaches[:3]]}
        return {'breached': False, 'count': 0, 'breaches': []}
    except:
        return {'breached': False, 'count': 0, 'breaches': [], 'error': 'Could not check'}

def calculate_risk(answers, ssl_result, dns_result, breach_result):
    score = 0
    breakdown = []
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
    if ssl_result['status'] == 'invalid':
        score += 10
        breakdown.append({'category': 'Web Security', 'issue': 'Invalid SSL', 'points': 10, 'severity': 'high'})
    if dns_result.get('spf') == 'missing':
        score += 5
        breakdown.append({'category': 'Email Security', 'issue': 'SPF missing', 'points': 5, 'severity': 'medium'})
    if dns_result.get('dmarc') == 'missing':
        score += 5
        breakdown.append({'category': 'Email Security', 'issue': 'DMARC missing', 'points': 5, 'severity': 'medium'})
    if breach_result.get('breached'):
        score += 8
        breakdown.append({'category': 'Dark Web', 'issue': f"{breach_result['count']} breaches found", 'points': 8, 'severity': 'high'})
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
        recs.append({'type': 'danger', 'icon': '🚨', 'category': 'Critical', 'text': 'Enable MFA immediately — blocks 99% of automated attacks.'})
    if answers['antivirus'] == 'no':
        recs.append({'type': 'danger', 'icon': '🚨', 'category': 'Critical', 'text': 'Install antivirus — Malwarebytes or Windows Defender are free.'})
    if answers['backups'] == 'no':
        recs.append({'type': 'danger', 'icon': '🚨', 'category': 'Critical', 'text': 'Set up daily backups — ransomware can destroy your data permanently.'})
    if ssl_result['status'] == 'invalid':
        recs.append({'type': 'danger', 'icon': '🔒', 'category': 'Web Security', 'text': 'SSL certificate invalid — customer data is NOT encrypted on your website.'})
    if dns_result.get('spf') == 'missing':
        recs.append({'type': 'warning', 'icon': '📧', 'category': 'Email Security', 'text': 'SPF missing — attackers can send emails pretending to be your company.'})
    if dns_result.get('dmarc') == 'missing':
        recs.append({'type': 'warning', 'icon': '📧', 'category': 'Email Security', 'text': 'DMARC missing — your email domain is vulnerable to spoofing.'})
    if breach_result.get('breached'):
        recs.append({'type': 'danger', 'icon': '🌑', 'category': 'Dark Web', 'text': f"Email found in {breach_result['count']} breaches — change all passwords immediately."})
    if answers['training'] == 'no':
        recs.append({'type': 'warning', 'icon': '👥', 'category': 'Staff Training', 'text': '90% of breaches start with phishing — schedule cybersecurity training.'})
    if answers['passwords'] == 'no':
        recs.append({'type': 'warning', 'icon': '🔑', 'category': 'Passwords', 'text': 'Use Bitwarden (free) to generate and store strong unique passwords.'})
    if answers['encryption'] == 'no':
        recs.append({'type': 'warning', 'icon': '🛡️', 'category': 'Encryption', 'text': 'Enable BitLocker on Windows — it is free and built-in.'})
    if not recs:
        recs.append({'type': 'success', 'icon': '✅', 'category': 'All Clear', 'text': 'Excellent! Strong security practices. Schedule quarterly reviews.'})
    return recs

def generate_attack_simulation(company_name, domain, answers, ssl_result, dns_result):
    from openai import OpenAI
    client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))
    issues = []
    if answers['mfa'] == 'no':
        issues.append("MFA is not enabled")
    if answers['antivirus'] == 'no':
        issues.append("No antivirus software")
    if answers['backups'] == 'no':
        issues.append("No data backups")
    if answers['training'] == 'no':
        issues.append("Staff have no cybersecurity training")
    if answers['passwords'] == 'no':
        issues.append("Weak password policies")
    if answers['encryption'] == 'no':
        issues.append("No data encryption")
    if ssl_result.get('status') == 'invalid':
        issues.append("Invalid SSL certificate")
    if dns_result.get('spf') == 'missing':
        issues.append("SPF record missing")
    if dns_result.get('dmarc') == 'missing':
        issues.append("DMARC record missing")
    issues_text = '\n'.join(f"- {i}" for i in issues) if issues else "- No major issues found"
    prompt = f"""You are a cybersecurity expert. Write a realistic attack simulation for a small business.
Company: {company_name}
Domain: {domain}
Vulnerabilities:
{issues_text}
Write exactly 4 steps showing how a hacker would attack this business. Each step 1-2 sentences. Use company name. Plain English. Start each with "Step X:"."""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400,
            temperature=0.7
        )
        simulation = response.choices[0].message.content
        steps = []
        for line in simulation.split('\n'):
            line = line.strip()
            if line.startswith('Step') and ':' in line:
                steps.append(line.split(':', 1)[1].strip())
        return steps if steps else ["Simulation generated — review your vulnerabilities above."]
    except:
        return [
            f"Attacker scans {domain} and finds missing SPF record — email spoofing is possible.",
            f"Phishing email sent from fake {domain} address to all staff — looks completely legitimate.",
            "Staff member clicks link — no MFA means attacker instantly has full account access.",
            "Ransomware deployed — no backups means business cannot recover without paying ransom."
        ]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        existing = Company.query.filter_by(email=email).first()
        if existing:
            return render_template('register.html', error='Email already registered. Please login.')
        company = Company(
            company_name=request.form.get('company_name'),
            email=email,
            password=generate_password_hash(request.form.get('password')),
            industry=request.form.get('industry'),
            employees=request.form.get('employees'),
            domain=request.form.get('domain', '')
        )
        db.session.add(company)
        db.session.commit()
        login_user(company)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        company = Company.query.filter_by(email=email).first()
        if company and check_password_hash(company.password, password):
            login_user(company)
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    assessments = Assessment.query.filter_by(
        company_id=current_user.id
    ).order_by(Assessment.created_at.desc()).all()
    latest = assessments[0] if assessments else None
    attack_steps = []
    recommendations = []
    if latest:
        answers = {
            'antivirus': latest.antivirus,
            'mfa': latest.mfa,
            'backups': latest.backups,
            'training': latest.training,
            'passwords': latest.passwords,
            'encryption': latest.encryption,
        }
        ssl_result = {'status': latest.ssl_status}
        dns_result = {'spf': latest.spf_status, 'dmarc': latest.dmarc_status}
        breach_result = {'breached': latest.breach_found, 'count': 0, 'breaches': []}
        attack_steps = generate_attack_simulation(
            current_user.company_name,
            current_user.domain or '',
            answers, ssl_result, dns_result
        )
        recommendations = generate_recommendations(answers, ssl_result, dns_result, breach_result)
    return render_template('dashboard.html',
        assessments=assessments,
        latest=latest,
        attack_steps=attack_steps,
        recommendations=recommendations
    )

@app.route('/assessment')
@login_required
def assessment():
    return render_template('assessment.html')

@app.route('/results', methods=['POST'])
@login_required
def results():
    domain = request.form.get('domain', current_user.domain or '').strip()
    email = request.form.get('email', current_user.email or '').strip()
    answers = {
        'antivirus': request.form.get('antivirus', 'no'),
        'mfa': request.form.get('mfa', 'no'),
        'backups': request.form.get('backups', 'no'),
        'training': request.form.get('training', 'no'),
        'passwords': request.form.get('passwords', 'no'),
        'encryption': request.form.get('encryption', 'no'),
    }
    if domain and not validate_domain(domain):
        return render_template('assessment.html',
            error='This domain does not exist. Please enter a real business domain.')
    ssl_result = check_ssl(domain) if domain else {'status': 'not_checked', 'days_left': 0, 'expires': 'N/A'}
    shodan_result = check_ports(domain) if domain else {'found': False, 'ports': [], 'closed': [], 'ip': None, 'total': 0}
    dns_result = check_dns(domain) if domain else {'spf': 'not_checked', 'dmarc': 'not_checked'}
    breach_result = check_breach(email) if email else {'breached': False, 'count': 0, 'breaches': []}
    score, risk_level, risk_message, breakdown = calculate_risk(answers, ssl_result, dns_result, breach_result)
    recommendations = generate_recommendations(answers, ssl_result, dns_result, breach_result)
    attack_simulation = generate_attack_simulation(
        current_user.company_name, domain, answers, ssl_result, dns_result)
    new_assessment = Assessment(
        company_id=current_user.id,
        score=score,
        risk_level=risk_level,
        antivirus=answers['antivirus'],
        mfa=answers['mfa'],
        backups=answers['backups'],
        training=answers['training'],
        passwords=answers['passwords'],
        encryption=answers['encryption'],
        ssl_status=ssl_result['status'],
        spf_status=dns_result.get('spf', 'unknown'),
        dmarc_status=dns_result.get('dmarc', 'unknown'),
        breach_found=breach_result.get('breached', False)
    )
    db.session.add(new_assessment)
    db.session.commit()
    return render_template('results.html',
        company_name=current_user.company_name,
        industry=current_user.industry,
        employees=current_user.employees,
        domain=domain,
        score=score,
        risk_level=risk_level,
        risk_message=risk_message,
        breakdown=breakdown,
        recommendations=recommendations,
        attack_simulation=attack_simulation,
        answers=answers,
        ssl_result=ssl_result,
        dns_result=dns_result,
        breach_result=breach_result,
        shodan_result=shodan_result,
        assessment_id=new_assessment.id
    )

@app.route('/port-scanner', methods=['GET', 'POST'])
@login_required
def port_scanner():
    result = None
    domain = ''
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if domain:
            if not validate_domain(domain):
                return render_template('port_scanner.html',
                    error='This domain does not exist.',
                    domain=domain, result=None)
            result = check_ports(domain)
    return render_template('port_scanner.html',
        domain=domain, result=result, error=None)

@app.route('/live-monitor')
@login_required
def live_monitor():
    assessments = Assessment.query.filter_by(
        company_id=current_user.id
    ).order_by(Assessment.created_at.desc()).all()
    latest = assessments[0] if assessments else None
    port_result = None
    ssl_result = None
    dns_result = None
    if latest and current_user.domain:
        port_result = check_ports(current_user.domain)
        ssl_result = check_ssl(current_user.domain)
        dns_result = check_dns(current_user.domain)
    return render_template('live_monitor.html',
        latest=latest,
        assessments=assessments,
        port_result=port_result,
        ssl_result=ssl_result,
        dns_result=dns_result,
        domain=current_user.domain or ''
    )

@app.route('/ai-advisor', methods=['POST'])
@login_required
def ai_advisor():
    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))
        data = request.get_json()
        question = data.get('question', '')
        assessments = Assessment.query.filter_by(
            company_id=current_user.id
        ).order_by(Assessment.created_at.desc()).all()
        latest = assessments[0] if assessments else None
        context = f"""You are an AI Security Advisor for {current_user.company_name}.
Company: {current_user.company_name}
Industry: {current_user.industry}
Domain: {current_user.domain}
Risk Score: {latest.score if latest else 'N/A'}/100
Risk Level: {latest.risk_level if latest else 'N/A'}
SSL: {latest.ssl_status if latest else 'N/A'}
SPF: {latest.spf_status if latest else 'N/A'}
DMARC: {latest.dmarc_status if latest else 'N/A'}
MFA: {latest.mfa if latest else 'N/A'}
Antivirus: {latest.antivirus if latest else 'N/A'}
Backups: {latest.backups if latest else 'N/A'}
Answer in plain English. Be specific. Max 3-4 sentences."""
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": context},
                {"role": "user", "content": question}
            ],
            max_tokens=200,
            temperature=0.7
        )
        return jsonify({'answer': response.choices[0].message.content})
    except Exception as e:
        return jsonify({'answer': f'Error: {str(e)}'})

@app.route('/download-pdf/<int:assessment_id>')
@login_required
def download_pdf(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    if assessment.company_id != current_user.id:
        return redirect(url_for('dashboard'))
    answers = {
        'antivirus': assessment.antivirus,
        'mfa': assessment.mfa,
        'backups': assessment.backups,
        'training': assessment.training,
        'passwords': assessment.passwords,
        'encryption': assessment.encryption,
    }
    ssl_result = {'status': assessment.ssl_status, 'expires': 'N/A', 'days_left': 0}
    dns_result = {'spf': assessment.spf_status, 'dmarc': assessment.dmarc_status}
    breach_result = {'breached': assessment.breach_found, 'count': 0, 'breaches': []}
    attack_simulation = generate_attack_simulation(
        current_user.company_name, current_user.domain or '',
        answers, ssl_result, dns_result)
    recommendations = generate_recommendations(answers, ssl_result, dns_result, breach_result)
    score, risk_level, risk_message, breakdown = calculate_risk(answers, ssl_result, dns_result, breach_result)
    pdf_buffer = generate_pdf_report(
        company_name=current_user.company_name,
        industry=current_user.industry,
        employees=current_user.employees,
        domain=current_user.domain or '',
        score=score,
        risk_level=risk_level,
        risk_message=risk_message,
        recommendations=recommendations,
        breakdown=breakdown,
        answers=answers,
        ssl_result=ssl_result,
        dns_result=dns_result,
        breach_result=breach_result,
        attack_simulation=attack_simulation
    )
    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'CyberRiskAI_{current_user.company_name}_{datetime.datetime.now().strftime("%Y%m%d")}.pdf'
    )

@app.route('/waitlist', methods=['POST'])
def waitlist():
    return redirect(url_for('register'))

if __name__ == '__main__':
    app.run(debug=True)