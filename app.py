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
import asyncio
from playwright.async_api import async_playwright
import re
import base64

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


async def capture_pages(domain):
    results = []

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={'width': 1280, 'height': 800})

        try:
            start = datetime.datetime.now()
            try:
                await page.goto(f"https://{domain}", timeout=25000, wait_until='domcontentloaded')
                await page.wait_for_timeout(2000)
            except:
                await page.goto(f"http://{domain}", timeout=25000, wait_until='domcontentloaded')
                await page.wait_for_timeout(2000)
            load_time = (datetime.datetime.now() - start).total_seconds() * 1000

            home_url = page.url
            home_html = await page.content()
            home_screenshot = await page.screenshot(full_page=False)
            home_boxes = await get_element_boxes(page)

            alt_data = await page.evaluate('''() => {
                const imgs = Array.from(document.querySelectorAll('img'));
                return {
                    total: imgs.length,
                    missing: imgs.filter(i => !i.alt || i.alt.trim() === '').length
                };
            }''')

            results.append({
                'label': 'Homepage',
                'url': home_url,
                'screenshot': home_screenshot,
                'load_time': round(load_time),
                'findings': analyze_page(home_url, home_html, load_time, alt_data, home_boxes)
            })

            links = await page.eval_on_selector_all(
                'a', 'els => els.map(e => ({href: e.href, text: e.innerText}))'
            )

            discovered = {}
            label_keywords = {
                'Shop': ['shop', 'store', 'products', 'shop now', 'collection'],
                'About': ['about', 'about us', 'our story', 'who we are'],
                'Contact': ['contact', 'get in touch', 'contact us', 'reach us'],
                'Blog': ['blog', 'news', 'articles', 'insights'],
            }
            for link in links:
                text = (link.get('text') or '').lower().strip()
                href = link.get('href') or ''
                if domain in href:
                    for label, keywords in label_keywords.items():
                        if label not in discovered and any(k in text for k in keywords):
                            discovered[label] = href

            for label, url in list(discovered.items())[:4]:
                try:
                    start = datetime.datetime.now()
                    await page.goto(url, timeout=25000, wait_until='domcontentloaded')
                    await page.wait_for_timeout(2000)
                    load_time = (datetime.datetime.now() - start).total_seconds() * 1000

                    p_html = await page.content()
                    p_screenshot = await page.screenshot(full_page=False)
                    p_boxes = await get_element_boxes(page)

                    p_alt_data = await page.evaluate('''() => {
                        const imgs = Array.from(document.querySelectorAll('img'));
                        return {
                            total: imgs.length,
                            missing: imgs.filter(i => !i.alt || i.alt.trim() === '').length
                        };
                    }''')

                    results.append({
                        'label': label,
                        'url': page.url,
                        'screenshot': p_screenshot,
                        'load_time': round(load_time),
                        'findings': analyze_page(page.url, p_html, load_time, p_alt_data, p_boxes)
                    })
                except:
                    continue

        finally:
            await browser.close()

    return results


async def get_element_boxes(page):
    """Get real bounding boxes of key elements for annotation positioning"""
    boxes = {}

    # Password field
    try:
        pw_field = await page.query_selector('input[type="password"]')
        if pw_field:
            box = await pw_field.bounding_box()
            if box:
                boxes['password_field'] = box
    except:
        pass

    # Footer
    try:
        footer = await page.query_selector('footer')
        if footer:
            box = await footer.bounding_box()
            if box:
                boxes['footer'] = box
    except:
        pass

    # Nav
    try:
        nav = await page.query_selector('nav')
        if nav:
            box = await nav.bounding_box()
            if box:
                boxes['nav'] = box
    except:
        pass

    return boxes


def analyze_page(url, html, load_time_ms=None, alt_data=None, boxes=None):
    findings = []
    boxes = boxes or {}
    viewport_w, viewport_h = 1280, 800

    if url.startswith('http://'):
        findings.append({
            'severity': 'high',
            'name': 'Page loads without HTTPS',
            'text': 'Your browser shows "Not Secure" for this page. This is the first thing customers and search engines see, and it directly affects trust and SEO rankings.',
            'fix': "Enable HTTPS redirect at your hosting provider — most hosts and Let's Encrypt offer this for free in under 30 minutes.",
            'box': None
        })

    has_password_field = 'type="password"' in html or "type='password'" in html
    if has_password_field and url.startswith('http://'):
        findings.append({
            'severity': 'high',
            'name': 'Login or password form on an unencrypted page',
            'text': 'A form requesting a password is present on a page served over HTTP. Data submitted here could be intercepted in transit.',
            'fix': 'Enabling HTTPS site-wide resolves this automatically — no code changes needed.',
            'box': boxes.get('password_field')
        })

    current_year = 2026
    copyright_match = re.search(r'©\s*(\d{4})', html)
    if copyright_match:
        year = int(copyright_match.group(1))
        if year < current_year - 1:
            findings.append({
                'severity': 'low',
                'name': f'Footer shows an outdated copyright year ({year})',
                'text': 'A copyright year that is several years old can signal to visitors and search engines that the site may not be actively maintained.',
                'fix': 'Update your footer template to show the current year, ideally generated dynamically.',
                'box': boxes.get('footer')
            })

    cookie_keywords = ['cookie consent', 'accept cookies', 'we use cookies', 'cookie policy', 'manage cookies']
    if not any(k in html.lower() for k in cookie_keywords):
        findings.append({
            'severity': 'medium',
            'name': 'No cookie consent banner detected',
            'text': 'UK GDPR and PECR generally require consent before setting non-essential cookies. We did not detect a cookie consent banner on this page.',
            'fix': 'Add a cookie consent banner — free tools like Osano or CookieYes can be added with a single script tag.',
            'box': None
        })

    if load_time_ms is not None and load_time_ms > 3000:
        findings.append({
            'severity': 'medium',
            'name': f'Slow page load — {load_time_ms/1000:.1f} seconds',
            'text': 'Pages that take over 3 seconds to load often see higher visitor drop-off rates.',
            'fix': 'Compress images, enable browser caching, and consider a CDN.',
            'box': None
        })

    if alt_data and alt_data['total'] > 0 and alt_data['missing'] > 0:
        findings.append({
            'severity': 'low',
            'name': f"{alt_data['missing']} of {alt_data['total']} images missing alt text",
            'text': 'Alt text helps screen readers describe images to visually impaired visitors and helps search engines understand your content.',
            'fix': 'Add descriptive alt attributes to all <img> tags.',
            'box': None
        })

    if not findings:
        findings.append({
            'severity': 'good',
            'name': 'No major visual issues found on this page',
            'text': 'This page appears to be well configured based on the checks performed.',
            'fix': 'No action needed — continue monitoring periodically.',
            'box': None
        })

    if boxes.get('nav') and any(f['severity'] != 'good' for f in findings):
        findings.append({
            'severity': 'good',
            'name': 'Navigation and branding look professional',
            'text': 'Clear navigation structure detected — a layout customers recognise and trust.',
            'fix': 'No action needed — this is a strength to maintain.',
            'box': boxes.get('nav')
        })

    # Convert pixel boxes to percentage positions for responsive display
    for f in findings:
        if f.get('box'):
            b = f['box']
            f['pos'] = {
                'left_pct': round((b['x'] + b['width']/2) / viewport_w * 100, 1),
                'top_pct': round((b['y']) / viewport_h * 100, 1)
            }
        else:
            f['pos'] = None

    return findings

def scan_api_endpoint(url):
    result = {
        'url': url,
        'findings': [],
        'response_fields': None,
        'requires_auth': None,
        'grade': 'A'
    }

    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    try:
        resp = requests.get(url, timeout=15, headers={'User-Agent': 'CyberRiskAI-Scanner'})

        # HTTPS check
        if url.startswith('https://'):
            result['findings'].append({
                'severity': 'good',
                'name': 'HTTPS enforced',
                'text': 'Data in transit between client and server is encrypted.',
                'fix': 'No action needed.',
                'owasp': None
            })
        else:
            result['findings'].append({
                'severity': 'high',
                'name': 'No HTTPS — unencrypted endpoint',
                'text': 'This API endpoint is served over plain HTTP. Data sent to and from it can be intercepted in transit.',
                'fix': 'Move this endpoint to HTTPS. Most hosting providers offer free SSL certificates.',
                'owasp': 'API8:2023 - Security Misconfiguration'
            })

        # Auth check
        if resp.status_code == 200:
            result['requires_auth'] = False
            result['findings'].append({
                'severity': 'high',
                'name': 'No authentication required',
                'text': 'This endpoint returned a response with no API key, token, or login required. If this returns business or customer data, anyone who finds this URL can access it.',
                'fix': 'Require an API key, token, or session authentication for any endpoint returning non-public data.',
                'owasp': 'API1:2023 - Broken Object Level Authorization'
            })

            # Try to extract field names only (not values) from JSON response
            try:
                data = resp.json()
                fields = extract_field_names(data)
                result['response_fields'] = fields[:15]
            except:
                pass

        elif resp.status_code in [401, 403]:
            result['requires_auth'] = True
            result['findings'].append({
                'severity': 'good',
                'name': 'Authentication required',
                'text': f'This endpoint returned a {resp.status_code} response — it requires authentication before returning data.',
                'fix': 'No action needed.',
                'owasp': None
            })
        else:
            result['findings'].append({
                'severity': 'low',
                'name': f'Endpoint returned status {resp.status_code}',
                'text': 'This may be expected depending on how the endpoint is designed.',
                'fix': 'Confirm this status code is expected for this endpoint.',
                'owasp': None
            })

        # CORS check
        cors = resp.headers.get('Access-Control-Allow-Origin')
        if cors == '*':
            result['findings'].append({
                'severity': 'medium',
                'name': 'CORS allows all origins (*)',
                'text': 'This API can be called from any website. Combined with weak authentication, this increases the risk of malicious sites making requests on a user\'s behalf.',
                'fix': 'Restrict Access-Control-Allow-Origin to only the domains that need to call this API.',
                'owasp': 'API8:2023 - Security Misconfiguration'
            })
        elif cors:
            result['findings'].append({
                'severity': 'good',
                'name': 'CORS restricted to specific origins',
                'text': f'Access-Control-Allow-Origin is set to a specific value, not a wildcard.',
                'fix': 'No action needed.',
                'owasp': None
            })

        # Rate limiting check
        rate_headers = ['X-RateLimit-Limit', 'RateLimit-Limit', 'X-Rate-Limit-Limit', 'Retry-After']
        if not any(h in resp.headers for h in rate_headers):
            result['findings'].append({
                'severity': 'medium',
                'name': 'No rate limiting detected',
                'text': 'No standard rate-limit headers were found in the response. This may mean repeated requests are not throttled, which can lead to abuse or denial-of-service.',
                'fix': 'Implement rate limiting (e.g. via API gateway) and return standard rate-limit headers.',
                'owasp': 'API4:2023 - Unrestricted Resource Consumption'
            })
        else:
            result['findings'].append({
                'severity': 'good',
                'name': 'Rate limiting headers present',
                'text': 'This endpoint returns rate-limit information, indicating requests are throttled.',
                'fix': 'No action needed.',
                'owasp': None
            })

        # Server info disclosure
        server_header = resp.headers.get('Server', '')
        if server_header and any(v in server_header.lower() for v in ['/', 'apache/', 'nginx/', 'express']):
            result['findings'].append({
                'severity': 'low',
                'name': f'Server software version disclosed ({server_header})',
                'text': 'The response reveals specific server software and version, which can help an attacker identify known vulnerabilities.',
                'fix': 'Configure your server to suppress or generalise the Server header.',
                'owasp': 'API8:2023 - Security Misconfiguration'
            })
        else:
            result['findings'].append({
                'severity': 'good',
                'name': 'No detailed server info disclosed',
                'text': 'The response does not reveal specific server software versions.',
                'fix': 'No action needed.',
                'owasp': None
            })
            # Sensitive data pattern detection
        try:
            body_text = resp.text
            sensitive_patterns = {
                'AWS Access Key': r'AKIA[0-9A-Z]{16}',
                'Stripe Live Key': r'sk_live_[0-9a-zA-Z]{20,}',
                'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
                'Generic API Key pattern': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][0-9a-zA-Z]{16,}["\']',
                'Private Key Header': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
                'Email addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            }
            found_sensitive = []
            for label, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, body_text)
                if matches:
                    found_sensitive.append({'label': label, 'count': len(matches)})

            critical_leaks = [f for f in found_sensitive if f['label'] != 'Email addresses']
            if critical_leaks:
                leak_names = ', '.join(f["label"] for f in critical_leaks)
                result['findings'].append({
                    'severity': 'high',
                    'name': f'Potential secrets exposed in response',
                    'text': f'The response body appears to contain patterns matching: {leak_names}. If real, these could allow unauthorised access to other systems.',
                    'fix': 'Immediately rotate any exposed keys/credentials. Never return secrets, keys, or credentials in API responses.',
                    'owasp': 'API3:2023 - Broken Object Property Level Authorization'
                })

            email_matches = [f for f in found_sensitive if f['label'] == 'Email addresses']
            if email_matches and result.get('requires_auth') == False:
                result['findings'].append({
                    'severity': 'medium',
                    'name': f'{email_matches[0]["count"]} email address(es) found in response',
                    'text': 'Email addresses were found in a response that requires no authentication. This may be expected for some public data, but worth reviewing for GDPR implications.',
                    'fix': 'Confirm this data is intended to be public. If it relates to customers or staff, restrict this endpoint.',
                    'owasp': 'API3:2023 - Broken Object Property Level Authorization'
                })
        except:
            pass

        # OPTIONS / allowed methods check
        try:
            opt_resp = requests.options(url, timeout=8, headers={'User-Agent': 'CyberRiskAI-Scanner'})
            allow_header = opt_resp.headers.get('Allow', '')
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(',')]
                risky_methods = [m for m in methods if m in ['PUT', 'DELETE', 'PATCH']]
                if risky_methods and result.get('requires_auth') == False:
                    result['findings'].append({
                        'severity': 'high',
                        'name': f'Write methods allowed without authentication ({", ".join(risky_methods)})',
                        'text': f'This endpoint advertises support for {", ".join(risky_methods)} alongside GET, with no authentication required for GET. If these methods are also unauthenticated, data could potentially be modified or deleted.',
                        'fix': 'Ensure all state-changing methods (PUT, DELETE, PATCH, POST) require authentication, even if GET does not.',
                        'owasp': 'API1:2023 - Broken Object Level Authorization'
                    })
        except:
            pass

    except requests.exceptions.RequestException as e:
        result['error'] = f'Could not reach this endpoint: {str(e)}'
        return result

    # Grade calculation
    severity_weights = {'high': 25, 'medium': 12, 'low': 5}
    score = 100
    for f in result['findings']:
        score -= severity_weights.get(f['severity'], 0)
    score = max(0, score)

    if score >= 85: result['grade'] = 'A'
    elif score >= 70: result['grade'] = 'B'
    elif score >= 50: result['grade'] = 'C'
    elif score >= 30: result['grade'] = 'D'
    else: result['grade'] = 'F'

    result['score'] = score
    return result


def extract_field_names(data, prefix=''):
    """Extract field NAMES only (not values) from a JSON response, for privacy"""
    fields = []
    if isinstance(data, dict):
        for k, v in data.items():
            field_path = f"{prefix}.{k}" if prefix else k
            fields.append(field_path)
            if isinstance(v, (dict, list)) and len(fields) < 20:
                fields.extend(extract_field_names(v, field_path))
    elif isinstance(data, list) and data:
        if isinstance(data[0], dict):
            fields.extend(extract_field_names(data[0], prefix + '[]'))
    return fields

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
    try:
        from groq import Groq
        client = Groq(api_key=os.environ.get('GROQ_API_KEY'))
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
        response = client.chat.completions.create(
            model="llama3-8b-8192",
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
    attack_simulation_result = generate_attack_simulation(
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
        attack_simulation=attack_simulation_result,
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
        from groq import Groq
        client = Groq(api_key=os.environ.get('GROQ_API_KEY'))
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
            model="llama-3.1-8b-instant",
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
    attack_simulation_result = generate_attack_simulation(
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
        attack_simulation=attack_simulation_result
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

@app.route('/attack-surface', methods=['GET', 'POST'])
@login_required
def attack_surface():
    assessments = Assessment.query.filter_by(
        company_id=current_user.id
    ).order_by(Assessment.created_at.desc()).all()
    latest = assessments[0] if assessments else None
    port_result = None
    ssl_result = None
    dns_result = None
    domain = request.args.get('domain', current_user.domain or '')
    if domain:
        port_result = check_ports(domain)
        ssl_result = check_ssl(domain)
        dns_result = check_dns(domain)
    return render_template('attack_surface.html',
        latest=latest,
        port_result=port_result,
        ssl_result=ssl_result,
        dns_result=dns_result,
        domain=domain
    )

@app.route('/threat-map')
@login_required
def threat_map():
    assessments = Assessment.query.filter_by(
        company_id=current_user.id
    ).order_by(Assessment.created_at.desc()).all()
    latest = assessments[0] if assessments else None
    return render_template('threat_map.html',
        latest=latest,
        domain=current_user.domain or ''
    )

@app.route('/ai-advisor-page')
@login_required
def ai_advisor_page():
    assessments = Assessment.query.filter_by(
        company_id=current_user.id
    ).order_by(Assessment.created_at.desc()).all()
    latest = assessments[0] if assessments else None
    return render_template('ai_advisor.html',
        latest=latest,
        domain=current_user.domain or ''
    )

@app.route('/vulnerability-scanner', methods=['GET', 'POST'])
@login_required
def vulnerability_scanner():
    result = None
    domain = ''
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if domain:
            if not validate_domain(domain):
                return render_template('vulnerability_scanner.html',
                    error='Domain does not exist.',
                    domain=domain, result=None,
                    latest=None)
            ssl_result = check_ssl(domain)
            dns_result = check_dns(domain)
            port_result = check_ports(domain)
            result = {
                'ssl': ssl_result,
                'dns': dns_result,
                'ports': port_result,
            }
    assessments = Assessment.query.filter_by(
        company_id=current_user.id
    ).order_by(Assessment.created_at.desc()).all()
    latest = assessments[0] if assessments else None
    return render_template('vulnerability_scanner.html',
        domain=domain,
        result=result,
        latest=latest,
        error=None
    )

@app.route('/attack-simulation')
@login_required
def attack_simulation():
    assessments = Assessment.query.filter_by(
        company_id=current_user.id
    ).order_by(Assessment.created_at.desc()).all()
    latest = assessments[0] if assessments else None
    port_result = None
    if latest and current_user.domain:
        port_result = check_ports(current_user.domain)
    return render_template('attack_simulation.html',
        latest=latest,
        port_result=port_result,
        domain=current_user.domain or ''
    )

def calculate_trust_score(pages):
    total_score = 100
    severity_weights = {'high': 12, 'medium': 6, 'low': 3}
    for pg in pages:
        for f in pg['findings']:
            total_score -= severity_weights.get(f['severity'], 0)
    return max(0, min(100, total_score))

def generate_web_advice(domain, pages):
    try:
        from groq import Groq
        client = Groq(api_key=os.environ.get('GROQ_API_KEY'))

        summary_lines = []
        for pg in pages:
            issues = [f['name'] for f in pg['findings'] if f['severity'] != 'good']
            summary_lines.append(f"{pg['label']} ({pg['url']}) — load time {pg.get('load_time','?')}ms — issues: {', '.join(issues) if issues else 'none'}")

        prompt = f"""You are a web consultant advising a UK small business about their website at {domain}.
Here is what was found across {len(pages)} pages:
{chr(10).join(summary_lines)}

Write a short paragraph (4-6 sentences) of plain-English advice. Identify the root cause if multiple issues share one (e.g. HTTPS). Mention which pages are clean. End with a realistic estimate of impact if fixed. No headers, no bullet points, just one paragraph."""

        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=250,
            temperature=0.6
        )
        return response.choices[0].message.content
    except:
        total_issues = sum(len([f for f in pg['findings'] if f['severity'] != 'good']) for pg in pages)
        return f"We found {total_issues} issue(s) across {len(pages)} pages on {domain}. Review the findings for each page above and prioritise high-severity issues first — these typically have the biggest impact on visitor trust and security."


@app.route('/web-app-scanner', methods=['GET', 'POST'])
@login_required
def web_app_scanner():
    result = None
    domain = ''
    error = None
    trust_score = None
    advice = None
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if domain:
            if not validate_domain(domain):
                error = 'Domain does not exist.'
            else:
                try:
                    pages = asyncio.run(capture_pages(domain))
                    for pg in pages:
                        pg['screenshot_b64'] = base64.b64encode(pg['screenshot']).decode('utf-8')
                    result = pages
                    trust_score = calculate_trust_score(pages)
                    advice = generate_web_advice(domain, pages)
                except Exception as e:
                    error = f'Scan failed: {str(e)}'
    return render_template('web_app_scanner.html',
        domain=domain, result=result, error=error,
        trust_score=trust_score, advice=advice)

@app.route('/api-security', methods=['GET', 'POST'])
@login_required
def api_security():
    result = None
    api_url = ''
    error = None
    if request.method == 'POST':
        api_url = request.form.get('api_url', '').strip()
        if api_url:
            result = scan_api_endpoint(api_url)
            if result.get('error'):
                error = result['error']
                result = None
    return render_template('api_security.html',
        api_url=api_url, result=result, error=error)

if __name__ == '__main__':
    app.run(debug=True)