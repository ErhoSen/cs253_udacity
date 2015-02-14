import webapp2
import jinja2
import os
import logging
from utils import *

from google.appengine.ext import db
from google.appengine.api import memcache

tenplate_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(tenplate_dir), autoescape= False)

def check_user_logged(cookie_str):
    if cookie_str:
        cookie_val = check_secure_val(cookie_str)
        if cookie_val:
            logging.error("ATTENTION AGAIN " + cookie_val)
            return memcache.get(str(cookie_val))

class Handler(webapp2.RedirectHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Pages(db.Model):
    page_key = db.StringProperty(required=True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)

class EditPage(Handler):
    def get(self, page_path=""):
        cookie_str = self.request.cookies.get('user_id')
        username = check_user_logged(cookie_str)
        page_key = "PAGE_" + page_path.replace('/', '')
        content = memcache.get(page_key)
        if content is None: content = ""
        self.render("edit.html", content=content, username=username)

    def post(self, page_path=""):
        page_name = page_path.replace('/', '')
        content = self.request.get('content')
        page_key = "PAGE_" + page_name
        if content:
            p = Pages(page_key = page_key, content = content)
            p.put()
            memcache.set(page_key, content)
            self.redirect(page_path)
        else:
            self.redirect(page_path)

class WikiPage(Handler):
    def get(self, page_path = ""):
        cookie_str = self.request.cookies.get('user_id')
        username = check_user_logged(cookie_str)
        page_name = page_path.replace('/', '')
        page_key = "PAGE_" + page_name
        content = memcache.get(page_key)
        if content is None and username:
            self.redirect('/_edit/' + page_name)
#            page = db.GqlQuery("SELECT * FROM Pages WHERE page_key = :page_key", page_key = page_key).get()
#            logging.error("WE REQUEST DB, BITCH!")
#            if page is None:
#                self.redirect('/_edit/' + page_path)
#            else:
#                content = page.content
#                memcache.set(page_key, content)
        else:
            if content is None: content = ""
            self.render("single_page.html", content=content, page_path=page_path, username=username)

class Signup(Handler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        users = db.GqlQuery(" SELECT * FROM Users")
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
            email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        elif username in [user.username for user in users]:
            params['error_username'] = "This user already exist"
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            pw_hash = make_pw_hash(username, password)
            u = Users(username = username, password = pw_hash, email = email)
            u.put()
            id = u.key().id()
            memcache.set(str(id), username)
            new_cookie = make_secure_val(str(id))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' %  new_cookie)
            self.redirect('/')

class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        buf = True
        user = ''
        try:
            user = (user for user in Users.all() if (user.username == username)).next()
        except StopIteration:
            buf = False
        if buf and user and valid_pw(username, password, user.password):
            id = user.key().id()
            new_cookie = make_secure_val(str(id))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' %  new_cookie)
            self.redirect('/')
        else:
            self.render('login-form.html', error_username = "Invalid login")

class Logout(Handler):
    def get(self):
        r_path = self.request.headers["Referer"].split('/')[-1]
        if r_path == '': r_path = '/'
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect(r_path)

class HistoryPage(Handler):
    def get(self, page_path = ""):
        cookie_str = self.request.cookies.get('user_id')
        username = check_user_logged(cookie_str)
        page_name = page_path.replace('/', '')
        # TODO: This function, ok?


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/signup', Signup), ('/login', Login),
    ('/logout', Logout),
    ('/_history' + PAGE_RE, HistoryPage),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, WikiPage),
    ], debug=True)

#app = webapp2.WSGIApplication([
#    ('/', MainHandler), ('/blog', BlogPage), ('/blog/signup', Signup),
#    ('/blog/login', Login), ('/blog/logout', Logout), ('/blog/welcome', Welcome),
#    ('/blog/newpost', NewPost), (r'/blog/([0-9]+)', SingleArticle), ('/blog/flush', Flush),
#    ('/askii', AskiiChan), ('/blog/?.json', BlogJson), (r'/blog/([0-9]+)/?.json', SingleJson)
#], debug=True)
