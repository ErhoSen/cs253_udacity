#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import time
import urllib2
import datetime
import json
import logging
from urllib2 import URLError
from xml.dom import minidom
from funcs import *
from google.appengine.ext import db
from google.appengine.api import memcache

QUERIED_TIME = time.time()
SINGLE_QUERIED_TIME = time.time()

tenplate_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(tenplate_dir), autoescape= True)

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content:
        d = minidom.parseString(content)
        coords = d.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon, lat = coords[0].childNodes[0].nodeValue.split(',')
            return db.GeoPt(lat, lon)

class Handler(webapp2.RedirectHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


def top_arts(update = False):
    key = "top"
    arts = memcache.get(key)

    if arts is None or update:
        logging.error("DB QUERY")
        arts = db.GqlQuery(" SELECT * "
                           "FROM Art "
                           "WHERE ANCESTOR IS :1 "
                           "ORDER BY created DESC "
                           "LIMIT 10")
        arts = list(arts)
        memcache.set(key, arts)
    return arts

def all_posts(update = False, q_time = None):
    global QUERIED_TIME
    key = "all"
    posts = memcache.get(key)

    if posts is None or update:
        logging.error("DB QUERY")
        QUERIED_TIME = time.time()
        posts = db.GqlQuery(" SELECT * FROM Post ORDER BY created DESC")
        posts = list(posts)
        memcache.set(key, posts)
    return posts

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()

class SingleArticle(Handler):

    def get(self, post_id):
        global SINGLE_QUERIED_TIME
        key = post_id
        post = memcache.get(key)
        if post is None:
            post = db.GqlQuery("SELECT * FROM Post").get().get_by_id(long(post_id))
            SINGLE_QUERIED_TIME = time.time()
            memcache.set(key, post)
        queried_time = "queried %d seconds ago" % (time.time() - SINGLE_QUERIED_TIME)
        self.render("single.html", post = post, queried_time = queried_time)

class BlogPage(Handler):
    def get(self):
        posts = all_posts()
        q_time = "queried %d seconds ago" % (time.time() - QUERIED_TIME)
        self.render("front.html", posts = posts, q_time = q_time)

class AskiiChan(Handler):
    def render_front(self, title="", art="", error=""):
        arts = top_arts()

        points = [a.coords for a in arts if a.coords]

        img_url = None
        print points
        if points:
            img_url = gmaps_img(points)

        self.render("askii_front.html", title=title, art=art, error=error, arts = arts, img_url = img_url)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get('title')
        art = self.request.get('art')

        if title and art:
            a = Art(title = title, art = art)
            #coords = get_coords(self.request.remote_addr)
            coords = get_coords("4.4.4.4")
            if coords:
                a.coords = coords
            a.put()
            top_arts(True)
            self.redirect("/askii")
        else:
            error = "we need both a title and some atrwork"
            self.render_front(title, art, error)

class MainHandler(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits+=1
        new_cookie_val = make_secure_val(str(visits))
        self.response.headers.add_header('Set-Cookie', 'visits=%s' %  new_cookie_val)
        if visits > 10000:
            self.write('Hay, cheater!')
        else:
            self.write("You've been here %s times!" % visits)

class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(subject = subject, content = content)
            p.put()
            all_posts(True)
            id = p.key().id()
            self.redirect("/blog/" + str(id))
        else:
            error = "subject and content please!"
            self.render('newpost.html', subject = subject, content = content, error = error)

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
            new_cookie = make_secure_val(str(id))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' %  new_cookie)
            self.redirect('/blog/welcome')

class Login(Handler):
    def valid_login(self):
        users = db.GqlQuery(" SELECT * FROM Users")

    def get(self):
        self.render("login-form.html")

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
            self.redirect('/blog/welcome')
        else:
            self.render('login-form.html', error_username = "Invalid login")

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog/signup')

class BlogJson(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        posts = db.GqlQuery(" SELECT * FROM Post ORDER BY created DESC")
        my_json = json.dumps([dict(content = post.content, created = post.created.strftime("%a %b %d %H:%M:%S %Y"),
            last_modified = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"), subject = post.subject) for post in posts])
        self.write(my_json)

class SingleJson(Handler):
    def get(self, post_id):
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        cur = db.GqlQuery("SELECT * FROM Post").get()
        post = cur.get_by_id(long(post_id))
        my_json = json.dumps(dict(content = post.content, created = post.created.strftime("%a %b %d %H:%M:%S %Y"),
            last_modified = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"), subject = post.subject))
        self.write(my_json)

class Welcome(Handler):
    def get(self):
        user_cookie_str = self.request.cookies.get('user_id')
        if user_cookie_str:
            cookie_val = check_secure_val(user_cookie_str)
            if cookie_val:
                cur = db.GqlQuery("SELECT * FROM Users").get()
                user = cur.get_by_id(long(cookie_val))
                self.render('welcome.html', username = user.username)
            else:
                self.redirect('/blog/signup')
        else:
            self.redirect('/blog/signup')

class Flush(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')

app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/blog', BlogPage), ('/blog/signup', Signup),
    ('/blog/login', Login), ('/blog/logout', Logout), ('/blog/welcome', Welcome),
    ('/blog/newpost', NewPost), (r'/blog/([0-9]+)', SingleArticle), ('/blog/flush', Flush),
    ('/askii', AskiiChan), ('/blog/?.json', BlogJson), (r'/blog/([0-9]+)/?.json', SingleJson)
], debug=True)
