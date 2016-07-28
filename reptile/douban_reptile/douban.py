#!/usr/bin/env python
#coding=utf-8

'''
豆瓣电影网站 爬虫
==== 需求
尚不明确

==== 豆瓣电影排行榜 URL
https://movie.douban.com/chart

==== 豆瓣新片排行榜
链接和标题
<a class="nbg" href="https://movie.douban.com/subject/25855071/"  title="初恋这首情歌">
正则表达式
<a\s+class="nbg"\s+href[\w:/.="]+\s+title="[^"]+

描述
<p class="pl">2016-03-18(爱尔兰) / 福迪亚·瓦尔什-匹罗 / 露西·宝通 / 杰克·莱诺 / 马克·麦克肯纳 / 艾丹·吉伦 / 玛利亚·多耶·肯尼迪 / 波西·钱布卡 / 康纳·汉密尔顿 / 爱尔兰 / 英国 / 美国 / 约翰·卡尼 / 106分钟 / 初恋这首情歌 / 剧情 / 爱情 / 音乐...</p>
正则表达式
<p\s+class="pl">[^<]+

评价人数
<span class="pl">(12645人评价)</span>
正则表达式
<span\s+class="pl">\([0-9]+

==== 本周口碑榜
未实现

==== 北美票房榜
未实现

==== 豆瓣电影TOP250
未实现

'''

import re
import sys
import json
import requests
from requests import ConnectionError
from threading import Thread

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


MOVIE_URL = 'https://movie.douban.com/chart'


class Movie():
    def __init__(self, url, title, des, comment, encoding):
        self.url = url
        self.title = title
        self.des = des
        self.comment = comment
        self.encoding = encoding

    def show(self):
        print self.title.encode(self.encoding).decode('utf-8')
        print 'des: ', self.des.encode(self.encoding).decode('utf-8')
        print 'comments: ', self.comment
        print 'url: ',self.url
        print

class NewMovieTop():
    def __init__(self, name):
        self.name = name
        self.tops = []

    def add(self, movie):
        self.tops.append(movie)

    def show(self):
        print u'\n============= %s =============\n'%self.name
        for top in self.tops:
            top.show()

class NewMovieTopFetcher():
    def __init__(self):
        self.url_title_reg = re.compile('<a\s+class="nbg"\s+href[\w:/.="]+\s+title="[^"]+')
        self.des_reg = re.compile('<p\s+class="pl">[^<]+')
        self.comment_reg = re.compile('<span\s+class="pl">\([0-9]+')
        self.url = []
        self.title = []
        self.des = []
        self.comment = []
        self.new_movie_tops = NewMovieTop(u'豆瓣新片排行榜')
        
    def _parse_url_title(self, rst):
        for line in rst:
            idx = line.rindex('"')
            self.title.append(line[idx+1:])
            idx2 = line.index('http', 0, idx-1)
            idx3 = line.rindex('"', idx2, idx-1)
            self.url.append(line[idx2:idx3])

    def _parse_des(self, rst):
        for line in rst:
            idx = line.index('>')
            self.des.append(line[idx+1:])

    def _parse_comment(self, rst):
        for line in rst:
            idx = line.index('(')
            self.comment.append(line[idx+1:])
            
    def get_min_count(self):
        min = len(self.url)
        #print 'count of url: %d'%min
        tmp = len(self.title)
        #print 'count of title: %d'%tmp
        if min < tmp:
            min = tmp
        tmp = len(self.des)
        #print 'count of des: %d'%tmp
        if min < tmp:
            min = tmp
        tmp = len(self.comment)
        #print 'count of comment: %d'%tmp
        if min < tmp:
            min = tmp
        return min
        
    def fetch_new_movie_top(self, text, encoding):
        url_title_rst = self.url_title_reg.findall(text)
        des_rst = self.des_reg.findall(text)
        comment_rst = self.comment_reg.findall(text)

        self._parse_url_title(url_title_rst)
        self._parse_des(des_rst)
        self._parse_comment(comment_rst)

        #print self.url
        #print self.title
        #print self.des
        #print self.comment

        min_count = self.get_min_count()
        #print min_count
        for idx in range(min_count):
            movie = Movie(self.url[idx], self.title[idx], self.des[idx], self.comment[idx], encoding)
            self.new_movie_tops.add(movie)
        
        return self.new_movie_tops

def done():
    try:
        req = requests.get(MOVIE_URL)
    except ConnectionError, e:
        print 'Connect error: ', e
        exit()
    print 'GET %s OK'%MOVIE_URL
#    sys.stdout.write(req.text)

    newmovietopfetch = NewMovieTopFetcher()
    new_movie_tops = newmovietopfetch.fetch_new_movie_top(req.text, req.encoding)

    new_movie_tops.show()

if __name__ == '__main__':
    done()
