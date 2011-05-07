#!/usr/bin/env python
#
# Meh, 2011, Eli James
# Hackboard, heavily hacked from some demo chat code for the Tornado webserver

import logging
import tornado.auth
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.web
import os.path
import uuid
import feedparser

from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/a/message/new", MessageNewHandler),
            (r"/a/message/updates", MessageUpdatesHandler),
            (r"/a/feed/new", FeedNewHandler),
        ]
        settings = dict(
            cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url="/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render("index.html", messages=MessageMixin.cache)


class MessageMixin(object):
    waiters = []
    cache = []
    cache_size = 200

    def wait_for_messages(self, callback, cursor=None):
        cls = MessageMixin
        if cursor:
            index = 0
            for i in xrange(len(cls.cache)):
                index = len(cls.cache) - i - 1
                if cls.cache[index]["id"] == cursor: break
            recent = cls.cache[index + 1:]
            if recent:
                callback(recent)
                return
        cls.waiters.append(callback)

    def new_messages(self, messages):
        cls = MessageMixin
        logging.info("Sending new message to %r listeners", len(cls.waiters))
        for callback in cls.waiters:
            try:
                callback(messages)
            except:
                logging.error("Error in waiter callback", exc_info=True)
        cls.waiters = []
        cls.cache.extend(messages)
        if len(cls.cache) > self.cache_size:
            cls.cache = cls.cache[-self.cache_size:]


class MessageNewHandler(BaseHandler, MessageMixin):
    @tornado.web.authenticated
    def post(self):
        message = {
            "id": str(uuid.uuid4()),
            "from": self.current_user["first_name"],
            "body": self.get_argument("body"),
            "feedmessage": False,
        }
        message["html"] = self.render_string("message.html", message=message)
        if self.get_argument("next", None):
            self.redirect(self.get_argument("next"))
        else:
            self.write(message)
        self.new_messages([message])


class MessageUpdatesHandler(BaseHandler, MessageMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def post(self):
        cursor = self.get_argument("cursor", None)
        self.wait_for_messages(self.async_callback(self.on_new_messages),
                               cursor=cursor)

    def on_new_messages(self, messages):
        # Closed client connection
        if self.request.connection.stream.closed():
            return
        self.finish(dict(messages=messages))


class FeedLoader(BaseHandler, MessageMixin):
    @tornado.web.asynchronous
    def get(self, add):
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(add,
                   callback=self.on_response)
    
    def on_response(self, response):
        if response.error: raise tornado.web.HTTPError(500)
        feed = feedparser.parse(response.body)
        author = d.entries[0].author.encode('utf-8')
        body = d.entries[0].title.encode('utf-8')
        message = {
               "id": str(uuid.uuid4()),
               "from": author,
               "body": body,
               "feedmessage": True,
           }
        message["html"] = self.render_string("message.html", message=message)
        self.finish()
        self.new_messages([message])
        

class FeedNewHandler(BaseHandler, MessageMixin):
    # Idea: use callback function for feedparsing, meanwhile just update todolist 
    @tornado.web.asynchronous
    def post(self):
        d = "%s/commits/master.atom" % self.get_argument("feedurl")
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(d,
                   callback=self.on_response)
                     
    def on_response(self, response):
        if response.error: raise tornado.web.HTTPError(500)
        feed = feedparser.parse(response.body)
        proj = feed.feed.title.encode('utf-8').split()[-1]
        message = {
                "id": str(uuid.uuid4()),
                "from": feed.entries[0].author.encode('utf-8'),
                "body": feed.entries[0].title.encode('utf-8') + " in " + proj,
                "feedmessage": True,
            }
        message["html"] = self.render_string("message.html", message=message)
        self.new_messages([message])
        if self.get_argument("next", None):
            self.redirect(self.get_argument("next"))
        else:
            self.write(feed.feed.title)
        self.finish()


class AuthLoginHandler(BaseHandler, tornado.auth.GoogleMixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("openid.mode", None):
            self.get_authenticated_user(self.async_callback(self._on_auth))
            return
        self.authenticate_redirect(ax_attrs=["name"])

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Google auth failed")
        self.set_secure_cookie("user", tornado.escape.json_encode(user))
        self.redirect("/")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.write("You are now logged out")


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
