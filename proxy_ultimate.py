# proxy_ultimate.py - Ultimate proxy untuk DNS Checker
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import json
import os
import mimetypes
import threading
import time
from urllib.parse import urlparse, unquote
import socket

class UltimateDNSProxy(BaseHTTPRequestHandler):
    # Konfigurasi
    BACKEND_URL = "http://127.0.0.1:5000"  # Flask backend
    FRONTEND_DIR = "templates"  # Folder untuk frontend
    STATIC_DIR = "static"  # Folder untuk static files (jika ada)
    
    # Cache untuk static files
    _cache = {}
    _cache_lock = threading.Lock()
    
    # Request counter untuk logging
    request_counter = 0
    
    def log_message(self, format, *args):
        """Custom logging yang lebih informatif"""
        self.request_counter += 1
        client_ip = self.client_address[0]
        print(f"[{self.request_counter:04d}] {self.date_time_string()} {client_ip} - {format % args}")
    
    def log_request(self, code='-', size='-'):
        """Override log_request untuk kontrol lebih"""
        pass  # Kita sudah handle di log_message
    
    def do_GET(self):
        """Handle GET requests"""
        self.handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests"""
        self.handle_request('POST')
    
    def do_PUT(self):
        """Handle PUT requests"""
        self.handle_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        self.handle_request('DELETE')
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self._add_cors_headers()
        self.end_headers()
    
    def do_HEAD(self):
        """Handle HEAD requests"""
        self.handle_request('HEAD', head_only=True)
    
    def handle_request(self, method, head_only=False):
        """Central request handler"""
        parsed_path = urlparse(self.path)
        path = unquote(parsed_path.path)
        
        # Log request
        print(f"📨 {method} {path}")
        
        # API requests -> proxy ke backend
        if path.startswith('/api/'):
            self._proxy_to_backend(method, path, head_only)
            return
        
        # WebSocket/Socket.IO -> proxy ke backend
        if path.startswith('/socket.io/'):
            self._proxy_to_backend(method, path, head_only)
            return
        
        # Static files
        if path.startswith('/static/'):
            self._serve_static_file(path, head_only)
            return
        
        # Root path -> serve index.html
        if path == '/' or path == '/index.html':
            self._serve_file('index.html', head_only)
            return
        
        # Coba serve file dari frontend directory
        file_path = self._resolve_file_path(path)
        if file_path and os.path.exists(file_path):
            self._serve_file_from_path(file_path, head_only)
        else:
            # Fallback: coba sebagai API atau 404
            if path.startswith('/'):
                self.send_error(404, f"File not found: {path}")
            else:
                self._proxy_to_backend(method, path, head_only)
    
    def _resolve_file_path(self, request_path):
        """Resolve file path dari request path"""
        # Remove leading slash
        if request_path.startswith('/'):
            request_path = request_path[1:]
        
        # Coba di frontend directory
        frontend_path = os.path.join(self.FRONTEND_DIR, request_path)
        if os.path.exists(frontend_path):
            return frontend_path
        
        # Coba di current directory
        if os.path.exists(request_path):
            return request_path
        
        # Coba dengan extension .html
        if not request_path.endswith('.html'):
            html_path = frontend_path + '.html'
            if os.path.exists(html_path):
                return html_path
        
        return None
    
    def _serve_file(self, filename, head_only=False):
        """Serve file dari frontend directory"""
        filepath = os.path.join(self.FRONTEND_DIR, filename)
        self._serve_file_from_path(filepath, head_only)
    
    def _serve_file_from_path(self, filepath, head_only=False):
        """Serve file dari path tertentu"""
        try:
            # Check cache dulu
            cache_key = (filepath, head_only)
            with self._cache_lock:
                if cache_key in self._cache and time.time() - self._cache[cache_key]['timestamp'] < 300:
                    cached = self._cache[cache_key]
                    self.send_response(200)
                    for key, value in cached['headers'].items():
                        self.send_header(key, value)
                    self.end_headers()
                    
                    if not head_only:
                        self.wfile.write(cached['content'])
                    print(f"✅ Served from cache: {filepath}")
                    return
            
            # Baca file
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Tentukan content type
            mime_type, _ = mimetypes.guess_type(filepath)
            if not mime_type:
                if filepath.endswith('.js'):
                    mime_type = 'application/javascript'
                elif filepath.endswith('.css'):
                    mime_type = 'text/css'
                elif filepath.endswith('.html'):
                    mime_type = 'text/html'
                else:
                    mime_type = 'application/octet-stream'
            
            # Kirim response
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'public, max-age=300')
            self._add_cors_headers()
            self.end_headers()
            
            if not head_only:
                self.wfile.write(content)
            
            # Cache file (kecuali HEAD request)
            if not head_only:
                with self._cache_lock:
                    self._cache[cache_key] = {
                        'content': content,
                        'headers': {
                            'Content-Type': mime_type,
                            'Content-Length': str(len(content)),
                            'Cache-Control': 'public, max-age=300'
                        },
                        'timestamp': time.time()
                    }
            
            print(f"✅ Served: {filepath}")
            
        except FileNotFoundError:
            self.send_error(404, f"File not found: {filepath}")
        except PermissionError:
            self.send_error(403, f"Permission denied: {filepath}")
        except Exception as e:
            print(f"❌ Error serving {filepath}: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def _serve_static_file(self, path, head_only=False):
        """Serve static files dari static directory"""
        # Remove /static/ prefix
        relative_path = path[8:] if path.startswith('/static/') else path
        filepath = os.path.join(self.STATIC_DIR, relative_path)
        
        if os.path.exists(filepath):
            self._serve_file_from_path(filepath, head_only)
        else:
            self.send_error(404, f"Static file not found: {path}")
    
    def _proxy_to_backend(self, method, path, head_only=False):
        """Proxy request ke backend Flask"""
        try:
            # Prepare URL
            url = f"{self.BACKEND_URL}{path}"
            
            # Prepare headers
            headers = {}
            for key, value in self.headers.items():
                key_lower = key.lower()
                # Filter out hop-by-hop headers
                if key_lower not in ['host', 'connection', 'keep-alive', 
                                     'proxy-authenticate', 'proxy-authorization',
                                     'te', 'trailers', 'transfer-encoding', 'upgrade']:
                    headers[key] = value
            
            # Prepare body
            body = None
            if method in ['POST', 'PUT', 'DELETE']:
                content_length = self.headers.get('Content-Length')
                if content_length:
                    content_length = int(content_length)
                    body = self.rfile.read(content_length)
            
            print(f"🔄 Proxying {method} {path} -> {url}")
            
            # Timeout configuration
            timeout = (10, 30)  # (connect timeout, read timeout)
            
            # Send request to backend
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=body, timeout=timeout)
            elif method == 'PUT':
                response = requests.put(url, headers=headers, data=body, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout)
            elif method == 'HEAD':
                response = requests.head(url, headers=headers, timeout=timeout)
            else:
                self.send_error(405, f"Method {method} not supported")
                return
            
            # Send response to client
            self.send_response(response.status_code)
            
            # Copy headers from backend response
            for key, value in response.headers.items():
                key_lower = key.lower()
                # Filter out hop-by-hop headers
                if key_lower not in ['connection', 'keep-alive', 'proxy-authenticate', 
                                     'proxy-authorization', 'te', 'trailers', 
                                     'transfer-encoding', 'upgrade']:
                    self.send_header(key, value)
            
            # Add CORS headers
            self._add_cors_headers()
            
            self.end_headers()
            
            # Send body if not HEAD request
            if not head_only and response.content:
                self.wfile.write(response.content)
            
            print(f"✅ Proxied {method} {path}: {response.status_code}")
            
        except requests.exceptions.ConnectionError:
            print(f"❌ Cannot connect to backend at {self.BACKEND_URL}")
            self.send_error(502, f"Backend unavailable at {self.BACKEND_URL}")
        except requests.exceptions.Timeout:
            print(f"❌ Backend timeout for {method} {path}")
            self.send_error(504, "Backend timeout")
        except requests.exceptions.RequestException as e:
            print(f"❌ Backend request error: {e}")
            self.send_error(502, f"Backend error: {str(e)}")
        except Exception as e:
            print(f"❌ Unexpected proxy error: {e}")
            self.send_error(500, f"Proxy error: {str(e)}")
    
    def _add_cors_headers(self):
        """Add CORS headers to response"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def send_error(self, code, message=None):
        """Override send_error untuk response JSON"""
        try:
            # Log error
            print(f"❌ Error {code}: {message}")
            
            # Send JSON error response
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self._add_cors_headers()
            self.end_headers()
            
            error_response = {
                "success": False,
                "error": {
                    "code": code,
                    "message": message or self.responses.get(code, ('Unknown', ''))[0]
                },
                "timestamp": time.time()
            }
            
            self.wfile.write(json.dumps(error_response).encode('utf-8'))
        except:
            super().send_error(code, message)

def check_backend_health():
    """Check if Flask backend is healthy"""
    try:
        response = requests.get("http://127.0.0.1:5000/api/test", timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Backend health check: {data.get('message', 'OK')}")
            return True
    except requests.exceptions.ConnectionError:
        print("❌ Backend not running")
    except Exception as e:
        print(f"⚠️  Backend health check warning: {e}")
    
    return False

def start_proxy_server(port=8000):
    """Start the proxy server"""
    # Initialize mimetypes
    mimetypes.init()
    
    print("=" * 60)
    print("           🚀 ULTIMATE DNS CHECKER PROXY")
    print("=" * 60)
    
    # Health check
    print("\n🔍 Checking backend health...")
    if not check_backend_health():
        print("\n⚠️  WARNING: Flask backend might not be running!")
        print("   Start it with: python app.py")
        print("   Continuing anyway...")
    
    print(f"\n📂 Frontend directory: {UltimateDNSProxy.FRONTEND_DIR}")
    print(f"📂 Static directory: {UltimateDNSProxy.STATIC_DIR}")
    print(f"🔗 Backend URL: {UltimateDNSProxy.BACKEND_URL}")
    
    try:
        server = HTTPServer(('0.0.0.0', port), UltimateDNSProxy)
        print(f"\n🚀 Proxy server starting on port {port}")
        print(f"🌐 Access frontend: http://localhost:{port}")
        print(f"📡 Proxy API calls to: {UltimateDNSProxy.BACKEND_URL}")
        print("\n📊 Features:")
        print("  • 🎯 Smart routing (API, static files, frontend)")
        print("  • 🔄 Full HTTP method support (GET, POST, PUT, DELETE, OPTIONS)")
        print("  • ⚡ File caching for performance")
        print("  • 🛡️  Comprehensive error handling")
        print("  • 📝 Detailed logging")
        print("  • 🔗 CORS headers automatically added")
        print("  • ⏱️  Request timeout handling")
        print("  • 💪 Health checks")
        print("\nPress Ctrl+C to stop")
        print("=" * 60)
        
        server.serve_forever()
        
    except PermissionError:
        print(f"\n❌ Permission denied for port {port}")
        print("   Try using a different port (e.g., 8080)")
    except OSError as e:
        if e.errno == 10048:
            print(f"\n❌ Port {port} is already in use")
            print("   Try using a different port (e.g., 8080)")
        else:
            print(f"\n❌ OS error: {e}")
    except KeyboardInterrupt:
        print("\n\n👋 Proxy server stopped by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
    finally:
        print("\n✅ Proxy server shutdown complete")

def check_dependencies():
    """Check and install required dependencies"""
    try:
        import requests
        return True
    except ImportError:
        print("📦 Installing required dependencies...")
        import subprocess
        import sys
        
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
            print("✅ Dependencies installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False

if __name__ == '__main__':
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Cannot start without required dependencies")
        input("Press Enter to exit...")
        exit(1)
    
    # Port configuration
    import sys
    port = 8000
    
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"⚠️  Invalid port: {sys.argv[1]}, using default port 8000")
    
    # Start the proxy server
    start_proxy_server(port)