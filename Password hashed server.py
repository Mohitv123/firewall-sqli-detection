# Python code using hashlib to hash the password created and stored in sqlite database 
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse, sqlite3, hashlib, os

DB_FILE = "users.db"
SERVER_PORT = 9090          
SALT = b"demo_salt_123"     

def hash_pwd(password: str) -> str:
    return hashlib.sha256(SALT + password.encode()).hexdigest()

def init_db():
    """Create table & a demo user if DB is new."""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
       # setting default credentials
        c.execute("SELECT 1 FROM users WHERE username = 'admin'")
        if not c.fetchone():
            c.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                      ('admin', hash_pwd('admin123')))
        conn.commit()

class MyHandler(BaseHTTPRequestHandler):                               # Connecting to the http server 

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            try:
                with open('index.html', 'rb') as f:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.send_error(404, "index.html not found")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode()
            params = urllib.parse.parse_qs(post_data)

            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]

            with sqlite3.connect(DB_FILE) as conn:                                 #Connecting to sqlite3 database
                c = conn.cursor()                                             
             
                c.execute("""
                    SELECT 1 FROM users
                    WHERE username = ? AND password_hash = ?
                """, (username, hash_pwd(password)))
                result = c.fetchone()

            self.send_response(200)
            self.end_headers()
            msg = b"Login successful!" if result else b"Login failed!"
            self.wfile.write(msg)
        else:
            self.send_error(404)

def run():                                          
    init_db()
    server_address = ('', 9090)
    httpd = HTTPServer(server_address, MyHandler)
    print(f"Server running at http://localhost:{9090}")                     # Running the webpage on http webserver using port 9090
    httpd.serve_forever()

if __name__ == '__main__':
    run()
