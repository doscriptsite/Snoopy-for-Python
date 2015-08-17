# -*- coding: utf-8 -*-
__author__ = 'Doscript'

__doc__ = """
Snoopy  -  一个强大的PHP采集库
Snoopy for python
By Doscript

原PHP库，详见
http://sourceforge.net/projects/snoopy/
PHP版本的解释：
Snoopy是一个php类，用来模拟浏览器的功能，可以获取网页内容，发送表单。
Snoopy的特点：
1、抓取网页的内容 fetch
2、抓取网页的文本内容 (去除HTML标签) fetchtext
3、抓取网页的链接，表单 fetchlinks fetchform
4、支持代理主机
5、支持基本的用户名/密码验证
6、支持设置 user_agent, referer(来路), cookies 和 header content(头文件)
7、支持浏览器重定向，并能控制重定向深度
8、能把网页中的链接扩展成高质量的url(默认)
9、提交数据并且获取返回值
10、支持跟踪HTML框架
11、支持重定向的时候传递cookies
要求php4以上就可以了，由于本身是php一个类，无需扩支持，服务器不支持curl时候的最好选择。
"""

import urllib
import urlparse
import re
import os
import socket
import zlib
import base64
import uuid
import hashlib


def gzinflate(base64_string):
    compressed_data = base64.b64decode(base64_string)
    return zlib.decompress(compressed_data, -15)

def empty(variable):
    if not variable:
        return True
    return False

def is_array(var):
    return isinstance(var, (list, tuple))

def isset(variable):
    return variable in locals() or variable in globals()

class Snoopy:
    
    """ Public variables """
    # usernamedefinable vars
    def __init__(self):
        self.scheme = 'http' # http or https
        self.host = "www.python.org" # host name we are connecting to
        self.port = 80 # port we are connecting to
        self.proxy_host = "" # proxy host to use
        self.proxy_port = "" # proxy port to use
        self.proxy_username= "" # proxy usernameto use
        self.proxy_password= "" # proxy password to use

        self.agent = "Snoopy for python v1.0.0" # agent we masquerade as
        self.referer = "" # referer info to pass
        self.cookies = {} # array of cookies to pass
        # cookies["username"]="joe"
        self.rawheaders = {} # array of raw headers to send
        # rawheaders["Content-type"]="text/html"

        self.maxredirs = 5 # http redirection depth maximum. 0 = disallow
        self.lastredirectaddr = "" # contains address of last redirected address
        self.offsiteok = True # allows redirection off-site
        self.maxframes = 0 # frame content depth maximum. 0 = disallow
        self.expandlinks = True # expand links to fully qualified URLs.
        # this only applies to fetchlinks()
        # submitlinks(), and submittext()
        self.passcookies = True # passwordset cookies back through redirects
        # NOTE: this currently does not respect
        # dates, domains or paths.

        self.username = "" # username for http authentication
        self.password = "" # password for http authentication

        # http accept types
        self.accept = "image/gif, image/x-xbitmap, image/jpeg, image/pjpeg,*"

        self.results = "" # where the content is put

        self.error = "" # error messages sent here
        self.response_code = "" # response code returned from server
        self.headers = {} # headers returned from server sent here
        self.maxlength = 500000 # max return data length (body)
        self.read_timeout = 0 # timeout on read operations, in seconds
        # supported only since PHP 4 Beta 4
        # set to 0 to disallow timeouts
        self.timed_out = False # if a read operation timed out
        self.status = 0 # http request status

        self.temp_dir = "/tmp" # temporary directory that the webserver
        # has permission to write to.
        # under Windows, this should be C:\temp

        self.curl_path = False
        # deprecated, snoopy no longer uses curl for https requests,
        # but instead requires the openssl extension.

        # send Accept-encoding: gzip?
        self.use_gzip = True

        # file or directory with CA certificates to verify remote host with
        self.cafile = ""
        self.capath = ""

        """ Private variables """

        self._maxlinelen = 4096 # max line length (headers)

        self._httpmethod = "GET" # default http request method
        self._httpversion = "HTTP/1.1" # default http request version
        self._submit_method = "POST" # default submit method
        self._submit_type = "application/x-www-form-urlencoded" # default submit type
        self._mime_boundary = "" # MIME boundary for multipart/form-data submit type
        self._redirectaddr = "" # will be set if page fetched is a redirect
        self._redirectdepth = 0 # increments on an http redirect
        self._frameurls = {} # frame src urls
        self._framedepth = 0 # increments on frame depth

        self._isproxy = False # set if using a proxy server
        self._fp_timeout = 30 # timeout for socket connection

        self.u8_bom = chr(239)+chr(187)+chr(191)

        """
            Function:    fetch
            Purpose:    fetch the contents of a web page
                        (and possibly other protocols in the
                        future like ftp, nntp, gopher, etc.)
            Input:        URI    the location of the page to fetch
            Output:        self.results    the output text from the fetch
        """

    def fetch(self, url):

        uri_rarts = urlparse.urlparse(url)
        if not empty(uri_rarts.username):
            self.username = uri_rarts.username
        if not empty(uri_rarts.password):
            self.password = uri_rarts.password

        fp = None

        switch = uri_rarts.scheme.lower()
        if switch == "https":
            self.port = 443
        elif switch ==  "http":
            self.scheme = uri_rarts.scheme.lower()
            self.host = uri_rarts.hostname
            if not empty(uri_rarts.port):
                self.port = uri_rarts.port
            fp = self._connect(fp)
            if fp:
                if self._isproxy:
                    # using proxy, send entire URI
                    self._httprequest(url, fp, url, self._httpmethod)
                else:
                    path = uri_rarts.path + ("?" + uri_rarts.query if uri_rarts.query else "")
                    # no proxy, send only the path
                    self._httprequest(path, fp, url, self._httpmethod)

                self._disconnect(fp)

                if self._redirectaddr:
                    #url was redirected, check if we've hit the max depth
                    if self.maxredirs > self._redirectdepth:
                        # only follow redirect if it's on this site, or offsiteok is True
                        if re.search("^https?://" + re.escape(self.host), self._redirectaddr, re.I) or self.offsiteok:
                            #follow the redirect
                            self._redirectdepth += 1
                            self.lastredirectaddr = self._redirectaddr
                            self.fetch(self._redirectaddr)

                if self._framedepth < self.maxframes and len(self._frameurls) > 0:
                    frameurls = self._frameurls
                    self._frameurls = {}

                    for frameurl in frameurls.values():
                        if self._framedepth < self.maxframes:
                            self.fetch(frameurl)
                            self._framedepth += 1
                        else:
                            break
            else:
                return False
            return self
        else:
            # not a valid protocol
            self.error = 'Invalid protocol "' + uri_rarts.scheme + '"\n'
            return False
        return self

    """
        Function:    submit
        Purpose:    submit an http(s) form
        Input:        URI    the location to post the data
                    formvars    the formvars to use.
                        format: formvars["var"] = "val"
                    formfiles  an array of files to submit
                        format: formfiles["var"] = "/dir/filename.ext"
        Output:        self.results    the text output from the post
    """

    def submit(self, uri, formvars = None, formfiles = None):
        postdata = self._prepare_post_body(formvars, formfiles)
        uri_rarts = urlparse.urlparse(uri)
        if not empty(uri_rarts.username):
            self.username= uri_rarts.username
        if not empty(uri_rarts.password):
            self.password= uri_rarts.password

        fp = None

        switch = uri_rarts.scheme.lower()
        if switch == "https":
            self.port = 443
        elif switch ==  "http":
            self.scheme = uri_rarts.scheme.lower()
            self.host = uri_rarts.hostname
            if not empty(uri_rarts.port):
                self.port = uri_rarts.port
            fp = self._connect(fp)
            if fp:
                if self._isproxy:
                    # using proxy, send entire URI
                    self._httprequest(uri, fp, uri, self._submit_method, self._submit_type, postdata)
                else:
                    path = uri_rarts.path + ("?" + uri_rarts.query if uri_rarts.query else "")
                    # no proxy, send only the path
                    self._httprequest(path, fp, uri, self._submit_method, self._submit_type, postdata)

                self._disconnect(fp)

                if self._redirectaddr:
                    #url was redirected, check if we've hit the max depth
                    if self.maxredirs > self._redirectdepth:
                        if not re.search("^" + uri_rarts.scheme + "://", self._redirectaddr):
                            self._redirectaddr = self._expandlinks(self._redirectaddr, uri_rarts.scheme + "://" + uri_rarts.host)

                        # only follow redirect if it's on this site, or offsiteok is True
                        if re.search("^https?://" + re.escape(self.host), self._redirectaddr, re.I) or self.offsiteok:
                            #follow the redirect
                            self._redirectdepth += 1
                            self.lastredirectaddr = self._redirectaddr
                            if self._redirectaddr.find("?") > 0:
                                self.fetch(self._redirectaddr) # the redirect has changed the request method from post to get
                            else:
                                self.submit(self._redirectaddr, formvars, formfiles)

                if self._framedepth < self.maxframes and len(self._frameurls) > 0:
                    frameurls = self._frameurls
                    self._frameurls = {}

                    for frameurl in frameurls.values():
                        if self._framedepth < self.maxframes:
                            self.fetch(frameurl)
                            self._framedepth += 1
                        else:
                            break

            else:
                return False
            return self
        else:
            # not a valid protocol
            self.error = 'Invalid protocol "' + uri_rarts.scheme + '"\n'
            return False
        return self

    """
        Function:    fetchlinks
        Purpose:    fetch the links from a web page
        Input:        URI    where you are fetching from
        Output:        self.results    an array of the URLs
    """

    def fetchlinks(self, uri):
        if self.fetch(uri):
            if self.lastredirectaddr:
                uri = self.lastredirectaddr
            if is_array(self.results):
                for i in xrange(len(self.results)):
                    self.results[i] = self._striplinks(self.results[i])
            else:
                self.results = self._striplinks(self.results)

            if self.expandlinks:
                self.results = self._expandlinks(self.results, uri)
            return self
        else:
            return False

    """
        Function:    fetchform
        Purpose:    fetch the form elements from a web page
        Input:        URI    where you are fetching from
        Output:        self.results    the resulting html form
    """

    def fetchform(self, uri):

        if self.fetch(uri):
            if is_array(self.results):
                for i in xrange(len(self.results)):
                    self.results[i] = self._stripform(self.results[i])
            else:
                self.results = self._stripform(self.results)
            return self
        else:
            return False


    """
        Function:    fetchtext
        Purpose:    fetch the text from a web page, stripping the links
        Input:        URI    where you are fetching from
        Output:        self.results    the text from the web page
    """

    def fetchtext(self, uri):
        if self.fetch(uri):
            if is_array(self.results):
                for i in xrange(len(self.results)):
                    self.results[i] = self._striptext(self.results[i])
            else:
                self.results = self._striptext(self.results)
            return self
        else:
            return False

    """
        Function:    submitlinks
        Purpose:    grab links from a form submission
        Input:        URI    where you are submitting from
        Output:        self.results    an array of the links from the post
    """

    def submitlinks(self, uri, formvars = "", formfiles = ""):
        if self.submit(uri, formvars, formfiles):
            if self.lastredirectaddr:
                uri = self.lastredirectaddr
            if is_array(self.results):
                for i in xrange(len(self.results)):
                    self.results[i] = self._striplinks(self.results[i])
                    if self.expandlinks:
                        self.results[i] = self._expandlinks(self.results[i], uri)
            else:
                self.results = self._striplinks(self.results)
                if self.expandlinks:
                    self.results = self._expandlinks(self.results, uri)
            return self
        else:
            return False

    """
        Function:    submittext
        Purpose:    grab text from a form submission
        Input:        URI    where you are submitting from
        Output:        self.results    the text from the web page
    """

    def submittext(self, uri, formvars = "", formfiles = ""):
        if self.submit(uri, formvars, formfiles):
            if self.lastredirectaddr:
                uri = self.lastredirectaddr
            if is_array(self.results):
                for i in xrange(len(self.results)):
                    self.results[i] = self._striptext(self.results[i])
                    if self.expandlinks:
                        self.results[i] = self._expandlinks(self.results[i], uri)
            else:
                self.results = self._striptext(self.results)
                if self.expandlinks:
                    self.results = self._expandlinks(self.results, uri)
            return self
        else:
            return False


    """
        Function:    set_submit_multipart
        Purpose:    Set the form submission content type to
                    multipart/form-data
    """
    def set_submit_multipart(self):
        self._submit_type = "multipart/form-data"
        return self


    """
        Function:    set_submit_normal
        Purpose:    Set the form submission content type to
                    application/x-www-form-urlencoded
    """
    def set_submit_normal(self):
        self._submit_type = "application/x-www-form-urlencoded"
        return self


    """
        Private functions
    """

    """
        Function:    _striplinks
        Purpose:    strip the hyperlinks from an html document
        Input:        document    document to strip.
        Output:        match        an array of the links
    """

    def _striplinks(self, document):
        links = re.findall("""<\s*a\s.*?href\s*=\s*            # find <a href=
                        [\"\']?                    # find single or double quote
                        (?(1) (.*?)\\1 | ([^\s\>]+))        # if quote found, match up to next matching
                                                    # quote, otherwise match up to next space
                        """, document, re.X | re.I | re.S)

        # catenate the non-empty matches from the conditional subpattern

        match = []
        for i in links:
            if not empty(i[1]):
                match.append(i[1])
            if not empty(i[0]):
                match.append(i[0])
        # return the links
        return match

    """
        Function:    _stripform
        Purpose:    strip the form elements from an html document
        Input:        document    document to strip.
        Output:        match        an array of the links
    """

    def _stripform(self, document):
        elements = re.findall("(<\/?(FORM|INPUT|SELECT|TEXTAREA|(OPTION))[^<>]*>(?(2)(.*(?=<\/?(option|select)[^<>]*>[\r\n]*)|(?=[\r\n]*))|(?=[\r\n]*)))", document, re.U | re.S | re.I)

        # catenate the matches
        match = "\r\n".join([i[0] for i in elements])

        # return the links
        return match


    """
        Function:    _striptext
        Purpose:    strip the text from an html document
        Input:        document    document to strip.
        Output:        text        the resulting text
    """

    def _striptext(self, document):
        # I didn't use preg eval (//e) since that is only available in PHP 4.0.
        # so, list your entities one by one here. I included some of the
        # more common ones.

        search = [('<script[^>]*?>.*?</script>', '', re.I | re.S),
                  ('<[\\/\\!]*?[^<>]*?>', '', re.I | re.S),
                  ('(?:[\r\n])[\\s]+', '\\1', 0),
                  ('&(?:quot|#34|#034|#x22);', '"', re.I),
                  ('&(?:amp|#38|#038|#x26);', '&', re.I),
                  ('&(?:lt|#60|#060|#x3c);', '<', re.I),
                  ('&(?:gt|#62|#062|#x3e);', '>', re.I),
                  ('&(?:nbsp|#160|#xa0);', ' ', re.I),
                  ('&(?:iexcl|#161);', chr(161), re.I),
                  ('&(?:cent|#162);', chr(162), re.I),
                  ('&(?:pound|#163);', chr(163), re.I),
                  ('&(?:copy|#169);', chr(169), re.I),
                  ('&(?:reg|#174);', chr(174), re.I),
                  ('&(?:deg|#176);', chr(176), re.I),
                  ('&(?:#39|#039|#x27);', chr(39), 0),
                  ('&(?:euro|#8364);', chr(128), re.I),
                  ('&a(?:uml|UML);', "ä", 0),
                  ('&o(?:uml|UML);', "ö", 0),
                  ('&u(?:uml|UML);', "ü", 0),
                  ('&A(?:uml|UML);', "Ä", 0),
                  ('&O(?:uml|UML);', "Ö", 0),
                  ('&U(?:uml|UML);', "Ü", 0),
                  ('&szlig;', "ß", re.I)]
        for i in search:
            document = re.sub(i[0], i[1], document, i[2])
        return document

    """
        Function:    _expandlinks
        Purpose:    expand each link into a fully qualified URL
        Input:        links            the links to qualify
                    URI            the full URI to get the base from
        Output:        expandedLinks    the expanded links
    """

    def _expandlinks(self, links, uri):
        match = re.search("^[^\?]+", uri)
        match = re.sub(r"/[^\/\.]+\.[^\/\.]+", "", match.group(1))
        match = re.sub("/", "", match)
        match_part = urlparse.urlparse(match)
        match_root = match_part.scheme + "://" + match_part.hostname
        #print match
        search = [("^http://" + re.escape(self.host), "", re.I),
                   ("^(\/)", match_root + "/", re.I),
                    ("^(?!http://)(?!mailto:)", match + "/", re.I),
                     ("/\./", "/", 0),
                      ("/[^\/]+/\.\./", "/", 0)]

        for i in search:
            links = re.sub(i[0], i[1], links, i[2])

        return links

    """
        Function:    _httprequest
        Purpose:    go get the http(s) data from the server
        Input:        url        the url to fetch
                    fp            the current open file pointer
                    URI        the full URI
                    body        body contents to send if any (POST)
        Output:
    """

    def _httprequest(self, url, fp, URI, http_method, content_type = "", body = ""):
        cookie_headers = ''
        if self.passcookies and self._redirectaddr:
            self.setcookies()

        URI_PARTS = urlparse.urlparse(URI)
        if empty(url):
            url = "/"
        headers = http_method + " " + url + " " + self._httpversion + "\r\n"
        if not empty(self.host) and 'Host' not in self.rawheaders:
            headers += "Host: " + self.host
            if (not empty(self.port) and self.port != '80'):
                headers += ":" + str(self.port)
            headers += "\r\n"
        if not empty(self.agent):
            headers += "User-Agent: " + self.agent + "\r\n"
        if not empty(self.accept):
            headers += "Accept: " + self.accept + "\r\n"
        if self.use_gzip:
            pass
        if not empty(self.referer):
            headers += "Referer: " + self.referer + "\r\n"
        if not empty(self.cookies):
            if len(self.cookies) > 0:
                cookie_headers += 'Cookie: '
                for cookieKey in self.cookies.keys():
                    cookie_headers += cookieKey + "=" + self.cookies[cookieKey] + "; "#urllib.quote_plus(self.cookies[cookieKey]) + "; "
                headers += cookie_headers[0:-1] + "\r\n"
        if not empty(self.rawheaders):
            for headerKey in self.rawheaders.keys():
                headers += headerKey + ": " + self.rawheaders[headerKey] + "\r\n"
        if not empty(content_type):
            headers += "Content-type: content_type"
            if content_type == "multipart/form-data":
                headers += " boundary=" + self._mime_boundary
            headers += "\r\n"
        if not empty(body):
            headers += "Content-length: " + str(len(body)) + "\r\n"
        if not empty(self.username) or not empty(self.password):
            headers += "Authorization: Basic " + (self.username + ":" + self.password).encode('base64') + "\r\n"

        #add proxy auth headers
        #if not empty(self.proxy_user):
        #    headers += 'Proxy-Authorization: ' + 'Basic ' + (self.proxy_username + ':' + self.proxy_pass).encode('base64') + "\r\n"

        headers += "\r\n"

        # set the read timeout if needed
        if self.read_timeout > 0:
            socket.setdefaulttimeout(self.read_timeout)
        self.timed_out = False
        fp.write(headers + body)
        fp.flush()

        self._redirectaddr = False
        self.headers = []

        # content was returned gzip encoded?
        is_gzipped = False

        while True:
            try:
                currentHeader = fp.readline(self._maxlinelen)
            except socket.timeout:
                self.status = -100
                return False
            if not currentHeader:
                break

            if currentHeader == "\r\n":
                break

            # if a header begins with Location: or URI:, set the redirect
            if re.search("^(Location:|URI:)", currentHeader, re.I):
                # get URL portion of the redirect
                matches = re.search("^(Location:|URI:)[ ]+(.*)", currentHeader.rstrip(), re.I)
                # look for :# in the Location header to see if hostname is included
                if not re.search("\:\/\/", matches.group(2)):
                    # no host in the path, so prepend
                    self._redirectaddr = URI_PARTS.scheme + "://" + self.host + ":" + self.port
                    # eliminate double slash
                    if not re.search("^/", matches.group(2)):
                        self._redirectaddr += "/" + matches.group(2)
                    else:
                        self._redirectaddr += matches.group(2)
                else:
                    self._redirectaddr = matches.group(2)

            if re.search("^HTTP/", currentHeader):
                status = re.search("^HTTP/[^\s]*\s(.*?)\s", currentHeader)
                if status:
                    self.status = status.group(1)
                self.response_code = currentHeader

            if re.search("Content-Encoding: gzip", currentHeader):
                is_gzipped = True

            self.headers.append(currentHeader)
        results = ''
        while True:
            try:
                _data = fp.read(self.maxlength)
            except socket.timeout:
                self.status = -100
                return False
            if len(_data) == 0:
                break
            results += _data
        if self.u8_bom in results:
            results = results[results.find(self.u8_bom) + 3:]
        # gunzip
        if is_gzipped:
            # per http://www.php.net/manual/en/function.gzencode.php
            results = results[10:]
            results = gzinflate(results)

        # check if there is a a redirect meta tag
        match = re.search("<meta[\s]*http-equiv[^>]*?content[\s]*=[\s]*[\"\']?\d+[\s]*URL[\s]*=[\s]*([^\"\']*?)[\"\']?>", results, re.I)
        if match:
            self._redirectaddr = self._expandlinks(match.group(1), URI)

        # have we hit our frame depth and is there frame src to fetch?
        match = re.findall("<frame\s+.*src[\s]*=[\'\"]?([^\'\"\>]+)", results, re.I)
        if (self._framedepth < self.maxframes) and match:
            self.results.append(results)
            for i in match:
                self._frameurls.append(self._expandlinks(i, URI_PARTS.scheme + "://" + self.host))
        # have we already fetched framed content?
        elif is_array(self.results):
            self.results.append(results)
        # no framed content
        else:
            self.results = results
        return self

    """
        Function:    setcookies()
        Purpose:    set cookies for a redirection
    """

    def setcookies(self):
        for i in self.headers:
            match = re.search("^set-cookie:[\s]+([^=]+)=([^;]+)", i, re.I)
            if match:
                self.cookies[match.group(1)] = urllib.unquote_plus(match.group(2))
        return self


    """
        Function:    _connect
        Purpose:    make a socket connection
        Input:        fp    file pointer
    """

    def _connect(self, fp):
        if not empty(self.proxy_host) and not empty(self.proxy_port):
            self._isproxy = True

            host = self.proxy_host
            port = self.proxy_port

            if self.scheme == 'https':
                print "HTTPS connections over proxy are currently not supported"
                return False
        else:
            host = self.host
            port = self.port

        self.status = 0

        context_opts = {}

        if self.scheme == 'https':
            # if cafile or capath is specified, enable certificate
            # verification (including name checks)
            context_opts['ssl'] = {
                    'verify_peer' : True,
                    'CN_match' : self.host,
                    'disable_compression' : True}

            context_opts['ssl']['cafile'] = self.cafile
            context_opts['ssl']['capath'] = self.capath

            host = 'ssl://' + host

        #context = stream_context_create(context_opts)
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #tcp socket
            sock.connect((host,port))
            fp = sock.makefile()
        except socket.error, msg:
            self.error = msg
        """
        if (version_compare(PHP_VERSION, '5.0.0', '>')) {
            if(self.scheme == 'http')
                host = "tcp://" . host
            fp = stream_socket_client(
                "host:port",
                errno,
                errmsg,
                self._fp_timeout,
                STREAM_CLIENT_CONNECT,
                context)
        } else {
            fp = fsockopen(
                host,
                port,
                errno,
                errstr,
                self._fp_timeout,
                context)
        }"""

        if fp:
            # socket connection succeeded
            return fp
        else:
            return False

    """
        Function:    _disconnect
        Purpose:    disconnect a socket connection
        Input:        fp    file pointer
    """

    def _disconnect(self, fp):
        fp.close()


    """
        Function:    _prepare_post_body
        Purpose:    Prepare post body according to encoding type
        Input:        formvars  - form variables
                    formfiles - form upload files
        Output:        post body
    """

    def _prepare_post_body(self, formvars, formfiles):
        postdata = ''

        if not formvars and not formfiles:
            return ""

        switch = self._submit_type
        if switch == "application/x-www-form-urlencoded":
            for i in formvars.keys():
                if is_array(formvars[i]):
                    for ii in formvars[i]:
                        postdata += urllib.unquote_plus(i) + "[]=" + urllib.unquote_plus(ii) + "&"
                else:
                    postdata += urllib.unquote_plus(i) + "=" + urllib.unquote_plus(formvars[i]) + "&"

        elif switch == "multipart/form-data":
            self._mime_boundary = "PYSnoopy" + hashlib.md5(uuid.uuid1()).hexdigest()
            for i in formvars.keys():
                if is_array(formvars[i]):
                    for ii in formvars[i]:
                        postdata += "--" + self._mime_boundary + "\r\n"
                        postdata += "Content-Disposition: form-data name=\"%s\[\]\"\r\n\r\n"%i
                        postdata += "%s\r\n"%ii
                else:
                    postdata += "--" + self._mime_boundary + "\r\n"
                    postdata += "Content-Disposition: form-data name=\"%s\"\r\n\r\n"%i
                    postdata += "%s\r\n"%formvars[i]

            for i in formfiles.keys():
                for ii in formfiles[i]:
                    if not os.access(ii, os.R_OK):
                        continue

                    fp = open(ii, "r")
                    file_content = fp.read()
                    fp.close()
                    base_name = os.path.basename(ii)

                    postdata += "--" + self._mime_boundary + "\r\n"
                    postdata += "Content-Disposition: form-data name=\"%s\" filename=\"%s\"\r\n\r\n"%(i, base_name)
                    postdata += "%s\r\n"%file_content
            postdata += "--" + self._mime_boundary + "--\r\n"

        return postdata

    """
    Function:    getResults
    Purpose:    return the results of a request
    Output:        string results
    """

    def getResults(self):
        return self.results

if __name__ == "__main__":
    test = Snoopy()
    test.expandlinks = True
    test.submit("http://www.douban.com/")
    print test.getResults()


