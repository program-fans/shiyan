#!/usr/bin/env python
#coding=utf-8

'''
新浪科技网站 爬虫

==== 需求
尚不明确

==== 新浪科技首页
http://tech.sina.com.cn/

==== 新浪域名第一个节点的部分含义
m	    新浪产品
finance	    新浪财经
games	    新浪游戏
sports	    新浪体育
down	    下载
down1	    下载
club	    新浪论坛
www	    新浪主页附属功能
corp	    新浪公司
comment5    新浪评论
tech	    新浪科技
roll	    图解新闻
slide	    新浪图片
blog	    新浪博客
news	    新浪新闻

==== 部分网址类型
新浪科技-新闻
http://tech.sina.com.cn/i/2016-07-25/doc-ifxuhukv7452304.shtml
新浪博客-博文
http://blog.sina.com.cn/s/blog_5d098bcc0102wol8.html?tj=tech 
科技热门新闻排行
http://tech.sina.com.cn/top/day_hotnews.shtml
新浪科技-围城
http://tech.sina.com.cn/surrounded.html
新浪数码
http://tech.sina.com.cn/digi/digi_dc/manufactor/manu_list.shtml
http://tech.sina.com.cn/digi/dc/search.html 
新浪科技-电脑
http://tech.sina.com.cn/notebook/review.shtml 
http://tech.sina.com.cn/notebook/new.shtml 
http://tech.sina.com.cn/notebook/buy.shtml
帮助
http://tech.sina.com.cn/focus/sinahelp.shtml

==== 正则表达式
新浪科技-新闻 和 博文 URL
http://(?:tech|blog)[\w\-\./]+(?:doc|blog)[\w-]+\.(?:htm|html|shtml)[\w\-\?=&]*

'''

import re
import sys
import json
import requests
from requests import ConnectionError
import threading
from threading import Thread
import time

try:
    from requests.packages.urllib3.exceptions import (
        SNIMissingWarning,
        InsecureRequestWarning,
        InsecurePlatformWarning
    )

# Not show warings
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
except ImportError:
    pass


START_URL = 'http://tech.sina.com.cn/'


class BlogSinatech(Thread):
    '''doc'''
    def __init__(self, url, blog_reg):
        self.url = url
        self.title = None
        self.keywords = None
        self.description = None
        self.encoding = None
        self.blog_reg = blog_reg
        self.error = None
        Thread.__init__(self)

    def _parse_blogs(self, blogs, text):
        for v in blogs:
            if v[1] == "keywords":
                idx = v[0].rindex('"') + 1
                self.keywords = v[0][idx:]
            elif v[1] == "description":
                idx = v[0].rindex('"') + 1
                self.description = v[0][idx:]
            else:
                pass
        ts = text.index('<title>')
        te = text.index('</title>')
        self.title = text[ts+len('<title>'):te]

    def blog_print(self):
        print self.url

        if self.error != None:
            print self.error
            print
            return
        
        if self.title != None:
            print u'title: %s'%self.title.encode(self.encoding).decode('utf-8')
        else:
            print u'title:'
        
        if self.keywords != None:
            print u'keywords: %s'%self.keywords.encode(self.encoding).decode('utf-8')
        else:
            print u'keywords:'

        if self.description != None:
            print u'description: %s'%self.description.encode(self.encoding).decode('utf-8')
        else:
            print u'description:'

        print

    def run(self):
        #print 'request ', self.url
        try:
            req = requests.get(self.url, timeout=10)
        except ConnectionError, e:
            print 'Connect error: ', e
            self.error = e
            return
        except Exception, e:
            print 'Error: ', e
            self.error = e
            return
        print 'GET %s OK'%self.url
        #print 'coding: ', req.encoding
        #print(req.text.encode(req.encoding).decode('utf-8'))

        self.encoding = req.encoding
        blogs = self.blog_reg.findall(req.text)
        self._parse_blogs(blogs, req.text)
        #self.blog_print()


class DocSinatech(Thread):
    '''doc'''
    def __init__(self, url, doc_reg):
        self.url = url
        self.title = None
        self.keywords = None
        self.description = None
        self.tags = None
        self.author = None
        self.publish_time = None
        self.type = None
        self.encoding = None
        self.error = None
        self.doc_reg = doc_reg
        Thread.__init__(self)

    def _parse_docs(self, docs):
        for v in docs:
            if v[1] == "keywords":
                idx = v[0].rindex('"') + 1
                self.keywords = v[0][idx:]
            elif v[1] == "description":
                idx = v[0].rindex('"') + 1
                self.description = v[0][idx:]
            elif v[1] == "tags":
                idx = v[0].rindex('"') + 1
                self.tags = v[0][idx:]
            elif v[1] == "og:type":
                idx = v[0].rindex('"') + 1
                self.type = v[0][idx:]
            elif v[1] == "og:title":
                idx = v[0].rindex('"') + 1
                self.title = v[0][idx:]
            elif v[1] == "article:published_time":
                idx = v[0].rindex('"') + 1
                self.publish_time = v[0][idx:]
            elif v[1] == "article:author":
                idx = v[0].rindex('"') + 1
                self.author = v[0][idx:]
            else:
                pass

    def doc_print(self):
        print self.url

        if self.error != None:
            print self.error
            print
            return
        
        if self.title != None:
            print u'title: %s'%self.title.encode(self.encoding).decode('utf-8')
        else:
            print u'title:'
        
        if self.keywords != None:
            print u'keywords: %s'%self.keywords.encode(self.encoding).decode('utf-8')
        else:
            print u'keywords:'
        
        if self.tags != None:
            print u'tags: %s'%self.tags.encode(self.encoding).decode('utf-8')
        else:
            print u'tags:'
        
        if self.type != None:
            print u'type: %s'%self.type.encode(self.encoding).decode('utf-8')
        else:
            print u'type:'

        if self.description != None:
            print u'description: %s'%self.description.encode(self.encoding).decode('utf-8')
        else:
            print u'description:'

        if self.publish_time != None:
            print u'publish_time: %s'%self.publish_time.encode(self.encoding).decode('utf-8')
        else:
            print u'publish_time:'

        if self.author != None:
            print u'author: %s'%self.author.encode(self.encoding).decode('utf-8')
        else:
            print u'author:'

        print
        
    def run(self):
        #print 'request ', self.url
        try:
            req = requests.get(self.url, timeout=10)
        except ConnectionError, e:
            #print 'Connect error: ', e
            self.error = e
            return
        except Exception, e:
            #print 'Error: ', e
            self.error = e
            return
        print 'GET %s OK'%self.url
        #print 'coding: ', req.encoding
        #print(req.text.encode(req.encoding).decode('utf-8'))

        self.encoding = req.encoding
        docs = self.doc_reg.findall(req.text)
        self._parse_docs(docs)
        #self.doc_print()

def show_doc(doc_thds, isShowErr = False):
    print u'\n===================== 新浪科技新闻 =====================\n'
    for dt in doc_thds:
        if dt.error != None and isShowErr == False:
            pass
        else:
            dt.doc_print()

def show_blog(blog_thds, isShowErr = False):
    print u'\n===================== 新浪科技博客 =====================\n'
    for bt in blog_thds:
        if bt.error != None and isShowErr == False:
            pass
        else:
            bt.blog_print()

def show_err_doc(doc_thds):
    print u'\n===================== doc errors =====================\n'
    for dt in doc_thds:
        if dt.error != None:
            dt.doc_print()

def show_err_blog(blog_thds):
    print u'\n===================== blog errors =====================\n'
    for bt in blog_thds:
        if bt.error != None:
            bt.blog_print()

def done():
    '''
'''
    reg = re.compile("http://(?:tech|blog)[\w\-\./]+(?:doc|blog)[\w-]+\.(?:htm|html|shtml)[\w\-\?=&]*")
    try:
        req = requests.get(START_URL)
    except ConnectionError, e:
        print 'Connect error: ', e
        exit()
    print 'GET %s OK'%START_URL
#    sys.stdout.write(req.text)

    rst = reg.findall(req.text)
    print 're.findall OK'
    #rst2 = list(set(rst))
    #据说用字典来处理列表去重，效率更高
    rst2 = {}.fromkeys(rst).keys()
    print 'Deduplication OK'
# 去重之后，顺序错乱，下面这个方法可以恢复之前的顺序
  #  rst2.sort(key=rst.index)
  #  print 'sort OK'
    print
    
    doc_reg = re.compile('(<meta[\s\w\-]+="(keywords|description|tags|og:type|og:title|article:published_time|article:author)"[\s\w]+="[^"]+)')
    blog_reg = re.compile('(<meta[\s\w\-]+="(keywords|description)"[\s\w]+="[^"]+)')

    #doc_thd = DocSinatech(rst2[0], doc_reg)
    #doc_thd.start()
    #doc_thd = DocSinatech(rst2[1], doc_reg)
    #doc_thd.start()

    doc_thds = []
    blog_thds = []
    for url in rst2:
        #print url
        #continue
        if url.rfind('doc') != -1:
            doc_thd = DocSinatech(url, doc_reg)
            doc_thd.start()
            doc_thds.append(doc_thd)
        elif url.find('blog') != -1:
            blog_thd = BlogSinatech(url, blog_reg)
            blog_thd.start()
            blog_thds.append(blog_thd)

    #print '================= create childs OK'
    while (threading.activeCount() > 1):
        time.sleep(1)

    show_doc(doc_thds, isShowErr = False)
    show_blog(blog_thds, isShowErr = False)

    show_err_doc(doc_thds)
    show_err_blog(blog_thds)


if __name__ == '__main__':
    done()
