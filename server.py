import cgi
import time
import http.server
import os
import ssl
import subprocess
import urllib
import random
import hashlib
import string
import binascii

PORT = 8080

tokens = {}

class token:
    def __init__(self, uuid, lifetime=900):
        self.uuid = uuid
        self.mktime = time.time()
        self.lifetime = lifetime

    def is_valid(self):
        return time.time() - self.mktime < self.lifetime

    def __eq__(x1, x2):
        return x1.uuid == x2.uuid

class passwordhash:
    def __init__(self, password, salt=0):
        self.algo = "sha256"
        if salt == 0:
            self.salt = os.urandom(32)
        else:
            self.salt = salt
        self.rounds = 1000000
        self.pwhash = hashlib.pbkdf2_hmac(
            self.algo,
            password,
            self.salt,
            self.rounds
        )
        
    def __str__(self):
        return("{}:{}:{}:{}".format(
            self.algo,
            binascii.hexlify(self.pwhash).decode("ascii"),
            binascii.hexlify(self.salt).decode("ascii"),
            self.rounds
        ))

    def __eq__(x1, x2):
        return x1.pwhash == x2.pwhash


users = {}

def useradd(username, password):
    if type(password) is str:
        password = password.encode("UTF8")
    pwhash = passwordhash(password)
    users[username] = user(username, pwhash)

def userdel(username):
    del users[username]

def passwd(username, password):
    user = users[username]
    if type(password) is str:
        password = password.encode("UTF8")
    user.password = passwordhash(password)

def chkpasswd(username, password):
    user = users[username]
    if type(password) is str:
        password = password.encode("UTF8")
    newhash = passwordhash(
        password,
        salt = user.password.salt
    )
    return newhash == user.password

class user:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __str__(self):
        return "username:{};password:{}".format(
            self.username,
            str(self.password)
        )

class post:
    def __init__(self, title, content, fname):
        self.title = title
        self.content = content
        self.fname = fname
        self.stat = os.stat("posts/{}".format(fname))
        self.ctime = self.stat.st_ctime
        self.comments = []

class req_handler(http.server.BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path.startswith("/comment-post-"):
            flength = int(self.headers.get('Content-Length'))
            postfname = self.path[len("/comment-post-"):]
            post = search_posts(postfname)
            DATA = PArse_form(self.rfile.read(flength))
            post.comments.append(data["comment"])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Posted okay")

        elif self.path == "/admin-auth":
            flength = int(self.headers.get('Content-Length'))
            data = parse_form(self.rfile.read(flength))

            if chkpasswd(data["username"], data["password"].encode("UTF8")):
                item = "".join(random.choice(string.ascii_letters + string.digits) for i in range(32))
                tokens[item] = token(item)
                self.send_response(200)
                self.send_header("Set-Cookie", "token={}".format(item))
                self.end_headers()
                self.wfile.write(b"logged in")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"login failed, either wrong username or wrong password")


    def do_GET(self):
        refresh_posts()

        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(genhtml().encode("UTF8"))

        elif not check_path("/home/jack/website", self.path[1:]):
            self.send_response(403)
            self.end_headers()
            self.wfile.write("request outside website sandbox")

        elif self.path == "/admin.html":
            t = self.headers.get("Cookie").split("=")[1]
                    
            if t in tokens:
                token = tokens[t]
                if token.is_valid():
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"You have authenticated with a correct token<br>")
                    self.wfile.write("Your token will only be valid for {} more seconds".format(
                        token.lifetime - (time.time() - token.mktime)
                    ).encode("UTF8"))
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"You have attempted to authenticate with a correct token, but it expired<br>")
                    self.wfile.write(b"Your token has been deleted, and trying again will look as if you're not logged in")
                    del tokens[t]
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"You are not logged in.")
                


        elif self.path.startswith("/posts/"):
            fname = self.path[len("/posts/"):]

            if self.path.endswith(".html"):
                fname = fname.replace(".html", ".md")
                post = search_posts(fname)
                self.send_response(200)
                self.send_header("Content-Type","text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(singlepost_template.format(
                    markdown(post.title),
                    markdown(post.content),
                    post.fname,
                    self.path.replace(".html", ".md"),
                    self.path.replace(".html", ".md.sig"),
                ).encode("UTF8"))

            elif self.path.endswith(".md") or self.path.endswith("md.sig"):
                self.send_response(200)
                self.send_header("Content-Type","text/plain; charset=utf-8")
                self.end_headers()
                with open(self.path[1:]) as f:
                    md = f.read()
                    self.wfile.write(md.encode("UTF8"))

            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"404 file not found")

        else:
            if os.path.isfile(self.path[1:]):
                self.send_response(200)
                self.end_headers()
                with open(self.path[1:], "rb") as f:
                    self.wfile.write(f.read())

def parse_form(data):
    output = {}
    data = data.decode("utf-8")
    for x in data.split("&"):
        item = x.split("=")
        output[item[0]] = urllib.parse.unquote_plus(item[1])
    return output

def check_path(sandbox, path):
    sbpath = os.path.abspath(sandbox)
    requested = os.path.relpath(path, sbpath)
    requested = os.path.abspath(requested)

    return sandbox == os.path.commonprefix([sandbox, requested])

def search_posts(fname):
    for post in posts:  
        if post.fname == fname:
            return post
    

def markdown(content):
    md = subprocess.Popen("/usr/bin/markdown", stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE)
    stdout, stderr = md.communicate(content.encode("UTF8"))
    stdout = stdout.strip()
    if stdout.startswith(b"<p>") and stdout.endswith(b"</p>"):
        stdout = stdout[3:-4]
        # This is done to strip out the <p>, as they're handled in the template
        # HTML file. However, when the code ends on a quote, a <blockquote>
        # tag is put on the very outside, and the <p> put inside that. No idea
        # if we should be putting the p outside in that case, but I need to in
        # order for the CSS to work

    return stdout.decode("UTF8")

def refresh_posts():
    global posts
    p = []
    for filename in sorted(os.listdir("posts"), key=lambda x:
                           os.path.getctime("posts/{}".format(x)))[::-1]:
        if filename.endswith(".md"):
            with open("posts/{}".format(filename)) as f:
                posttext = f.read()
                title = posttext.split("\n")[0]
                body = "\n".join(posttext.split("\n")[2:])
                p.append(post(title, body, filename))
    posts = p

def genhtml():

    poststext = []
    for item in posts:
        poststext.append(post_template.format(
            "<a href=posts/{}>{}</a>".format(item.fname.replace(".md", ".html"), markdown(item.title)),
            markdown(item.content),
        ))
    return index_template.format("".join(poststext))


def start_server(server_class=http.server.HTTPServer,
                 handler_class=http.server.BaseHTTPRequestHandler):
    server_addr = ("", PORT)
    httpd = server_class(server_addr, req_handler)
#    httpd.socket = ssl.wrap_socket(httpd.socket, certfile="priv/key.pem",
#                                   server_side=True)
    httpd.serve_forever()

with open("index-template.html") as f:
    index_template = f.read()

with open("post-template.html") as f:
    post_template = f.read()

with open("singlepost-template.html") as f:
    singlepost_template = f.read()

refresh_posts()

useradd("admin", b"hunter2")

assert chkpasswd("admin", b"hunter2")
assert not(chkpasswd("admin", b"hunter3"))

passwd("admin", "hunter2-!")
assert chkpasswd("admin", b"hunter2-!")
assert not(chkpasswd("admin", b"hunter2"))

assert "admin" in users

userdel("admin")

assert not("admin" in users)

print("self checks complete")
print("setting up admin user with default password")
useradd("admin", "hunter2")

start_server()
