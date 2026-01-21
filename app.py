# app.py - Vercel Deployment Version
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import dns.resolver
import dns.zone
import dns.query
import dns.dnssec
import dns.rdatatype
import concurrent.futures
import sqlite3
import json
import csv
import io
import pandas as pd
from datetime import datetime, timedelta
import threading
import time
import os
from functools import lru_cache
import logging

# Disable Redis for Vercel deployment
redis_available = False

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
CORS(app)
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='threading',
                   manage_session=False)

# Database setup for Vercel (in-memory or temporary file)
def init_db():
    """Initialize SQLite database - using in-memory for Vercel"""
    try:
        # Try to use persistent storage if available
        if os.environ.get('VERCEL'):
            # In Vercel, we use in-memory database
            conn = sqlite3.connect(':memory:')
        else:
            # Local development with file-based database
            os.makedirs('/tmp/database', exist_ok=True)
            conn = sqlite3.connect('/tmp/database/dns_checker.db')
        
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS dns_results
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      domain TEXT,
                      record_type TEXT,
                      server TEXT,
                      result TEXT,
                      response_time REAL,
                      timestamp DATETIME)''')
        c.execute('''CREATE TABLE IF NOT EXISTS propagation_checks
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      domain TEXT,
                      record_type TEXT,
                      status TEXT,
                      progress INTEGER,
                      start_time DATETIME,
                      last_update DATETIME)''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        # Fallback to in-memory
        pass

# Initialize database on startup
init_db()

def get_db_connection():
    """Get database connection - handles Vercel environment"""
    try:
        if os.environ.get('VERCEL'):
            # In Vercel, use in-memory database (data will be lost on cold start)
            return sqlite3.connect(':memory:', check_same_thread=False)
        else:
            # Local development
            return sqlite3.connect('/tmp/database/dns_checker.db', check_same_thread=False)
    except:
        # Ultimate fallback
        return sqlite3.connect(':memory:', check_same_thread=False)

# DNS Servers Configuration (same as before)
DNS_SERVERS = {
    "global": [
        {"name": "Cloudflare", "ipv4": "1.1.1.1", "ipv6": "2606:4700:4700::1111", "region": "Global", "emoji": "🌐"},
        {"name": "Google DNS", "ipv4": "8.8.8.8", "ipv6": "2001:4860:4860::8888", "region": "Global", "emoji": "🔵"},
        {"name": "Quad9", "ipv4": "9.9.9.9", "ipv6": "2620:fe::fe", "region": "Global", "emoji": "🛡️"},
        {"name": "OpenDNS", "ipv4": "208.67.222.222", "ipv6": "2620:119:35::35", "region": "Global", "emoji": "🔐"},
    ],
    "asia": [
        {"name": "DNS.SB", "ipv4": "185.222.222.222", "ipv6": "2a09::", "region": "Singapore/Germany", "emoji": "🚀"},
        {"name": "AliDNS", "ipv4": "223.5.5.5", "region": "China", "emoji": "🐉"},
        {"name": "DNSPod", "ipv4": "119.29.29.29", "region": "China", "emoji": "☁️"},
        {"name": "IIJ", "ipv4": "103.2.57.5", "region": "Japan", "emoji": "🎌"},
        {"name": "NTT", "ipv4": "129.250.35.250", "region": "Japan", "emoji": "🇯🇵"},
    ],
    "europe": [
        {"name": "Digitale Gesellschaft", "ipv4": "185.95.218.42", "region": "Switzerland", "emoji": "🇨🇭"},
        {"name": "FDN", "ipv4": "80.67.169.40", "region": "France", "emoji": "🇫🇷"},
        {"name": "SafeDNS", "ipv4": "195.46.39.39", "region": "UK", "emoji": "🇬🇧"},
        {"name": "Yandex DNS", "ipv4": "77.88.8.8", "region": "Russia", "emoji": "🇷🇺"},
    ],
    "north_america": [
        {"name": "Comodo DNS", "ipv4": "8.26.56.26", "region": "USA", "emoji": "🇺🇸"},
        {"name": "Level3", "ipv4": "4.2.2.1", "region": "USA", "emoji": "📶"},
        {"name": "Verisign", "ipv4": "64.6.64.6", "region": "USA", "emoji": "🔷"},
    ],
    "south_america": [
        {"name": "Arnet", "ipv4": "200.45.32.34", "region": "Argentina", "emoji": "🇦🇷"},
        {"name": "UOL DNS", "ipv4": "200.221.11.100", "region": "Brazil", "emoji": "🇧🇷"},
    ],
    "oceania": [
        {"name": "Optus", "ipv4": "211.29.132.12", "region": "Australia", "emoji": "🇦🇺"},
        {"name": "Spark NZ", "ipv4": "210.55.186.186", "region": "New Zealand", "emoji": "🇳🇿"},
    ],
    "special": [
        {"name": "AdGuard DNS", "ipv4": "94.140.14.14", "region": "Ad Blocking", "emoji": "🛡️"},
        {"name": "CleanBrowsing", "ipv4": "185.228.168.9", "region": "Family Filter", "emoji": "👨‍👩‍👧‍👦"},
        {"name": "UncensoredDNS", "ipv4": "91.239.100.100", "region": "No Censorship", "emoji": "🗽"},
    ]
}

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV', 'DNAME', 'CAA', 'DS', 'DNSKEY']

class DNSChecker:
    @staticmethod
    def lookup_record(domain, record_type, dns_server_ip, timeout=5):
        """Perform DNS lookup for a single server"""
        start_time = time.time()
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server_ip]
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            if record_type == 'PTR':
                answers = resolver.resolve_address(domain)
            else:
                answers = resolver.resolve(domain, record_type)
            
            results = []
            for rdata in answers:
                if record_type == 'MX':
                    results.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == 'SOA':
                    results.append(str(rdata))
                else:
                    results.append(str(rdata))
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            return {
                "status": "success",
                "results": results,
                "response_time": round(response_time, 2),
                "server_ip": dns_server_ip
            }
            
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain", "results": [], "response_time": round((time.time() - start_time) * 1000, 2), "server_ip": dns_server_ip}
        except dns.resolver.NoAnswer:
            return {"status": "noanswer", "results": [], "response_time": round((time.time() - start_time) * 1000, 2), "server_ip": dns_server_ip}
        except dns.resolver.Timeout:
            return {"status": "timeout", "results": [], "response_time": timeout * 1000, "server_ip": dns_server_ip}
        except Exception as e:
            return {"status": "error", "error": str(e), "response_time": round((time.time() - start_time) * 1000, 2), "server_ip": dns_server_ip}

# ============ ROUTES ============

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/test', methods=['GET'])
def test_api():
    """Test endpoint untuk cek backend berjalan"""
    return jsonify({
        "success": True,
        "message": "DNS Checker API is working!",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "status": "online",
        "environment": "Vercel" if os.environ.get('VERCEL') else "Development",
        "endpoints": [
            "/api/test",
            "/api/servers",
            "/api/dns-lookup",
            "/api/history",
            "/api/bulk-check",
            "/api/start-propagation",
            "/api/export/<format>"
        ]
    })

@app.route('/api/servers', methods=['GET'])
def get_servers():
    """Get all DNS servers configuration"""
    return jsonify(DNS_SERVERS)

@app.route('/api/server-count', methods=['GET'])
def get_server_count():
    """Get count of DNS servers per region"""
    counts = {region: len(servers) for region, servers in DNS_SERVERS.items()}
    total = sum(counts.values())
    
    return jsonify({
        "success": True,
        "total_servers": total,
        "counts": counts,
        "regions": list(DNS_SERVERS.keys())
    })

@app.route('/api/dns-lookup', methods=['POST'])
def dns_lookup():
    """Main DNS lookup endpoint"""
    data = request.json
    domain = data.get('domain')
    record_type = data.get('record_type', 'A')
    regions = data.get('regions', ['all'])
    custom_servers = data.get('custom_servers', [])
    timeout = data.get('timeout', 5)
    max_concurrent = data.get('max_concurrent', 10)
    
    if not domain:
        return jsonify({"success": False, "error": "Domain is required"}), 400
    
    # Validate domain format
    if not domain.replace('.', '').isalnum():
        return jsonify({"success": False, "error": "Invalid domain format"}), 400
    
    # Select servers based on regions
    selected_servers = []
    if 'all' in regions or not regions:
        for region_servers in DNS_SERVERS.values():
            selected_servers.extend(region_servers)
    else:
        for region in regions:
            if region in DNS_SERVERS:
                selected_servers.extend(DNS_SERVERS[region])
    
    # Add custom servers
    for server in custom_servers:
        if server:  # Skip empty strings
            selected_servers.append({
                "name": f"Custom: {server}",
                "ipv4": server,
                "region": "Custom",
                "emoji": "⚙️"
            })
    
    # Remove duplicates
    unique_servers = []
    seen_ips = set()
    for server in selected_servers:
        ip = server.get('ipv4')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_servers.append(server)
    
    if not unique_servers:
        return jsonify({"success": False, "error": "No valid DNS servers selected"}), 400
    
    results = []
    
    # Parallel DNS lookups
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_concurrent, len(unique_servers))) as executor:
        future_to_server = {
            executor.submit(
                DNSChecker.lookup_record,
                domain,
                record_type,
                server['ipv4'],
                timeout
            ): server for server in unique_servers if server.get('ipv4')
        }
        
        for future in concurrent.futures.as_completed(future_to_server):
            server = future_to_server[future]
            try:
                result = future.result(timeout=timeout+2)
                result.update({
                    "server_name": server['name'],
                    "region": server['region'],
                    "emoji": server.get('emoji', '🔵')
                })
                results.append(result)
                
                # Try to save to database (optional)
                try:
                    conn = get_db_connection()
                    c = conn.cursor()
                    c.execute('''INSERT INTO dns_results 
                                (domain, record_type, server, result, response_time, timestamp)
                                VALUES (?, ?, ?, ?, ?, ?)''',
                             (domain, record_type, server['name'], 
                              json.dumps(result), result['response_time'], 
                              datetime.now().isoformat()))
                    conn.commit()
                    conn.close()
                except Exception as db_error:
                    logger.warning(f"Could not save to database: {db_error}")
                    # Continue without saving
                
            except concurrent.futures.TimeoutError:
                results.append({
                    "server_name": server['name'],
                    "region": server['region'],
                    "emoji": server.get('emoji', '🔵'),
                    "status": "timeout",
                    "error": "DNS lookup timeout",
                    "response_time": timeout * 1000
                })
            except Exception as e:
                results.append({
                    "server_name": server['name'],
                    "region": server['region'],
                    "emoji": server.get('emoji', '🔵'),
                    "status": "error",
                    "error": str(e),
                    "response_time": 0
                })
    
    # Analyze results
    analysis = analyze_results(results)
    
    return jsonify({
        "success": True,
        "domain": domain,
        "record_type": record_type,
        "results": results,
        "analysis": analysis,
        "total_servers": len(unique_servers),
        "timestamp": datetime.now().isoformat()
    })

def analyze_results(results):
    """Analyze DNS lookup results for consistency"""
    if not results:
        return {
            "total_checked": 0,
            "successful": 0,
            "failed": 0,
            "consistent": True,
            "success_rate": 0,
            "avg_response_time": 0,
            "min_response_time": 0,
            "max_response_time": 0,
        }
    
    successful = [r for r in results if r.get('status') == 'success']
    failed = [r for r in results if r.get('status') != 'success']
    
    # Check consistency among successful results
    consistent = True
    if successful:
        first_result = json.dumps(sorted(successful[0].get('results', [])))
        for result in successful[1:]:
            if json.dumps(sorted(result.get('results', []))) != first_result:
                consistent = False
                break
    
    # Response time stats
    response_times = [r.get('response_time', 0) for r in successful if r.get('response_time')]
    
    return {
        "total_checked": len(results),
        "successful": len(successful),
        "failed": len(failed),
        "consistent": consistent,
        "success_rate": round(len(successful) / len(results) * 100, 2) if results else 0,
        "avg_response_time": round(sum(response_times) / len(response_times), 2) if response_times else 0,
        "min_response_time": min(response_times) if response_times else 0,
        "max_response_time": max(response_times) if response_times else 0,
    }

@app.route('/api/bulk-check', methods=['POST'])
def bulk_check():
    """Handle bulk domain check from uploaded file"""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        if file and (file.filename.endswith('.txt') or file.filename.endswith('.csv')):
            content = file.read().decode('utf-8').strip()
            
            if file.filename.endswith('.csv'):
                # Parse CSV
                df = pd.read_csv(io.StringIO(content))
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
            else:
                # Parse TXT (one domain per line)
                domains = content.split('\n')
            
            domains = [d.strip() for d in domains if d.strip()]
            domains = domains[:50]  # Limit to 50 domains for performance
            
            results = []
            for domain in domains:
                # Perform A record check by default
                try:
                    result = DNSChecker.lookup_record(domain, 'A', '8.8.8.8')
                    results.append({
                        "domain": domain,
                        "has_a_record": result['status'] == 'success',
                        "ips": result.get('results', []),
                        "status": result['status']
                    })
                except Exception as e:
                    results.append({
                        "domain": domain,
                        "has_a_record": False,
                        "ips": [],
                        "status": "error",
                        "error": str(e)
                    })
            
            return jsonify({
                "success": True,
                "domains_checked": len(results),
                "results": results
            })
        
        return jsonify({"error": "Invalid file format. Use .txt or .csv"}), 400
    except Exception as e:
        logger.error(f"Bulk check error: {e}")
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get historical DNS check results"""
    limit = request.args.get('limit', 20, type=int)
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''SELECT * FROM dns_results 
                     ORDER BY timestamp DESC 
                     LIMIT ?''', (limit,))
        
        rows = c.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            try:
                result_data = json.loads(row[4]) if row[4] else {}
            except:
                result_data = {}
            
            history.append({
                "id": row[0],
                "domain": row[1],
                "record_type": row[2],
                "server": row[3],
                "result": result_data,
                "response_time": row[5],
                "timestamp": row[6]
            })
        
        return jsonify({"success": True, "history": history})
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify({"success": False, "error": str(e), "history": []}), 500

@app.route('/api/export/<format_type>', methods=['POST'])
def export_results(format_type):
    """Export results in various formats"""
    try:
        data = request.json
        results = data.get('results', [])
        analysis = data.get('analysis', {})
        domain = data.get('domain', 'export')
        record_type = data.get('record_type', '')
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == 'json':
            export_data = {
                "domain": domain,
                "record_type": record_type,
                "timestamp": datetime.now().isoformat(),
                "results": results,
                "analysis": analysis
            }
            return jsonify(export_data)
        
        elif format_type == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Server', 'Region', 'Status', 'Results', 'Response Time (ms)'])
            
            for result in results:
                writer.writerow([
                    result.get('server_name', 'Unknown'),
                    result.get('region', 'Unknown'),
                    result.get('status', 'Unknown'),
                    '; '.join(result.get('results', [])),
                    result.get('response_time', 0)
                ])
            
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'dns_check_{domain}_{timestamp}.csv'
            )
        
        elif format_type == 'txt':
            output = io.StringIO()
            output.write(f"DNS Check Report\n")
            output.write(f"================\n")
            output.write(f"Domain: {domain}\n")
            output.write(f"Record Type: {record_type}\n")
            output.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output.write(f"\nResults:\n")
            output.write(f"--------\n")
            
            for result in results:
                output.write(f"\nServer: {result.get('server_name')}\n")
                output.write(f"Region: {result.get('region')}\n")
                output.write(f"Status: {result.get('status')}\n")
                output.write(f"Response Time: {result.get('response_time')} ms\n")
                if result.get('results'):
                    output.write(f"Results: {', '.join(result.get('results', []))}\n")
                if result.get('error'):
                    output.write(f"Error: {result.get('error')}\n")
            
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/plain',
                as_attachment=True,
                download_name=f'dns_check_{domain}_{timestamp}.txt'
            )
        
        return jsonify({"error": "Unsupported format. Use json, csv, or txt"}), 400
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({"error": f"Export failed: {str(e)}"}), 500

# ============ SOCKET.IO ENDPOINTS (Optional - may not work on Vercel) ============

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected via Socket.IO')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

# ============ ERROR HANDLING ============

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found",
        "available_endpoints": [
            "/api/test",
            "/api/servers", 
            "/api/dns-lookup",
            "/api/history",
            "/api/bulk-check",
            "/api/export/<format>"
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({
        "success": False,
        "error": "Rate limit exceeded. Please try again later."
    }), 429

# ============ VERCEL SPECIFIC HANDLING ============

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /api/\nAllow: /", 200, {'Content-Type': 'text/plain'}

# ============ MAIN ENTRY POINT ============

# This is required for Vercel to detect the app
# Vercel will look for a variable named "app" (Flask instance)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    print("=" * 60)
    print("🚀 DNS CHECKER PRO - VERCEL DEPLOYMENT")
    print("=" * 60)
    print(f"📡 Running on port: {port}")
    print(f"🌐 Environment: {'Vercel' if os.environ.get('VERCEL') else 'Development'}")
    print(f"🗄️  Database: {'In-memory' if os.environ.get('VERCEL') else 'File-based'}")
    print(f"⚡ Redis: Disabled (Vercel limitation)")
    print("\n📋 Available Endpoints:")
    print("  GET  /                   - Frontend")
    print("  GET  /api/test           - Test API")
    print("  GET  /api/servers        - Get DNS servers")
    print("  GET  /api/server-count   - Get server counts")
    print("  POST /api/dns-lookup     - Check DNS")
    print("  GET  /api/history        - Get history")
    print("  POST /api/bulk-check     - Bulk domain check")
    print("  POST /api/export/<format>- Export results")
    print("=" * 60)
    
    # For Vercel, we don't run socketio
    if os.environ.get('VERCEL'):
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)