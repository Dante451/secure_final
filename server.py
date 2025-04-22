import http.server
import urllib.parse

# In-memory "database" (a simple dictionary to simulate a user store)
'''
---------------------------------------------------------------------------------
A02:2021-Cryptographic Failures
Storing a Plain text password in the code
---------------------------------------------------------------------------------
'''
users_db = {
    'admin': 'password123'
}

# Basic function to handle SQL Injection vulnerability
def check_login(username, password):
    # Simulating an SQL query, prone to injection
    '''
    ---------------------------------------------------------------------------------
    A03:2021-Injection
    Use parameterization for queries with untrusted input
    ---------------------------------------------------------------------------------
    '''
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    # "Checking" the database (in reality, just a dictionary lookup)
    if username in users_db and users_db[username] == password:
        return True
    return False

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Serve the login form
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
                <html><body>
                <h1>SQL Injection Test</h1>
                <form method="POST" action="/login">
                    Username: <input type="text" name="username"><br>
                    Password: <input type="password" name="password"><br>
                    <input type="submit" value="Login">
                </form>
                </body></html>
            ''')
        else:
            self.send_error(404, 'Page Not Found')

    def do_POST(self):
        # Handle login attempt
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            post_params = urllib.parse.parse_qs(post_data.decode())

            '''
            ---------------------------------------------------------------------------------
            A03:2021-Injection
            User input unsanitized enabling cross-site scripting attacks
            ---------------------------------------------------------------------------------
            '''
            username = post_params.get('username', [''])[0]
            password = post_params.get('password', [''])[0]

            # Check login (vulnerable to SQL injection)
            if check_login(username, password):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f"<h1>Welcome, {username}!</h1>".encode())
            else:
                self.send_response(401)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<h1>Invalid credentials!</h1>")

def run(server_class=http.server.HTTPServer, handler_class=SimpleHTTPRequestHandler):
    server_address = ('', 8080)  # Run on localhost:8080
    httpd = server_class(server_address, handler_class)
    print('Starting server at http://localhost:8080')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
