#!/usr/bin/env python
#coding=utf-8

"""
Train tickets query and display. The datas come
from:
    www.12306.cn
"""

import os
import re
import sys
import json
import requests
from utils import colored, exit_after_echo
from datetime import datetime
from collections import OrderedDict
from prettytable import PrettyTable
from requests.exceptions import ConnectionError
from utils import args, exit_after_echo

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


__all__ = ['query']


QUERY_URL = 'https://kyfw.12306.cn/otn/lcxxcx/query'

# ERROR MSG
FROM_STATION_NOT_FOUND = 'From station not found.'
TO_STATION_NOT_FOUND = 'To station not found.'
INVALID_DATE = 'Invalid query date.'
NETWORK_CONNECTION_FAIL = 'Network connection failed.'
TRAIN_NOT_FOUND = 'No result.'
NO_RESPONSE = 'Sorry, server is not responding.'


class TrainsCollection(object):

    """A set of raw datas from a query."""

    headers = '车次 车站 时间 历时 商务 一等 二等 软卧 硬卧 软座 硬座 无座 备注'.split()

    def __init__(self, rows, opts):
        self._rows = rows
        self._opts = opts

    def __repr__(self):
        return '<TrainsCollection size={}>'.format(len(self))

    def __iter__(self):
        i = 0
        while True:
            if i < len(self):
                yield self[i]
            else:
                yield next(self)
            i += 1

    def __len__(self):
        return len(self._rows)

    def _get_duration(self, row):
        duration = row.get('lishi').replace(':', u'小时') + u'分钟'
        # take 0 hour , only show minites
        if duration.startswith('00'):
            return duration[4:]
        # take <10 hours, show 1 bit
        if duration.startswith('0'):
            return duration[1:]
        return duration

    @property
    def trains(self):
        """Filter rows according to `headers`"""
        for row in self._rows:
            train_no = row.get('station_train_code')
            canWebBuy = row.get('canWebBuy')
            initial = train_no[0].lower()
            if not self._opts or initial in self._opts:
                if canWebBuy == 'Y':
                    train = [
                        # Column: '车次'
                        train_no,
                        # Column: '车站'
                        '\n'.join([
                            colored.green(row.get('from_station_name')),
                            colored.red(row.get('to_station_name')),
                        ]),
                        # Column: '时间'
                        '\n'.join([
                            colored.green(row.get('start_time')),
                            colored.red(row.get('arrive_time')),
                        ]),
                        # Column: '历时'
                        self._get_duration(row),
                        # Column: '商务'
                        row.get('swz_num'),
                        # Column: '一等'
                        row.get('zy_num'),
                        # Column: '二等'
                        row.get('ze_num'),
                        # Column: '软卧'
                        row.get('rw_num'),
                        # Column: '硬卧'
                        row.get('yw_num'),
                        # Column: '软座'
                        row.get('rz_num'),
                        # Column: '硬座'
                        row.get('yz_num'),
                        # Column: '无座'
                        row.get('wz_num'),
                        # Column: '备注'
                        '--'
                    ]
                else:
                  	train = [
                        train_no,
                        '\n'.join([
                            colored.green(row.get('from_station_name')),
                            colored.red(row.get('to_station_name')),
                        ]),
                        '\n'.join([
                            colored.green('-----'),
                            colored.red('-----'),
                        ]),
                        '--','--','--','--','--','--','--','--','--',
                        # Column: '备注'
                        row.get('controlled_train_message')
                    ]
                yield train

    def pretty_print(self):
        """Use `PrettyTable` to perform formatted outprint."""
        pt = PrettyTable()
        if len(self) == 0:
            pt._set_field_names(['Sorry,'])
            pt.add_row([TRAIN_NOT_FOUND])
        else:
            pt._set_field_names(self.headers)
            for train in self.trains:
                pt.add_row(train)
        print(pt)


class TrainTicketsQuery(object):

    """Docstring for TrainTicketsCollection. """

    def __init__(self, from_station, to_station, date, opts=None):

        self.from_station = from_station
        self.to_station = to_station
        self.date = date
        self.opts = opts

    def __repr__(self):
        return 'TrainTicketsQuery from={} to={} date={}'.format(
            self._from_station, self._to_station, self._date
        )

    @property
    def stations(self):
        filepath = os.path.join(
            os.path.dirname(__file__),
            'datas', 'stations.dat'
        )
        d = {}
        #with open(filepath, 'r', encoding='utf-8') as f:
        with open(filepath, 'r') as f:
            for line in f.readlines():
                name, telecode = line.split()
                d.setdefault(name, telecode)
        return d

    @property
    def _from_station_telecode(self):
        code = self.stations.get(self.from_station)
        if not code:
            exit_after_echo(FROM_STATION_NOT_FOUND)
        return code

    @property
    def _to_station_telecode(self):
        code = self.stations.get(self.to_station)
        if not code:
            exit_after_echo(TO_STATION_NOT_FOUND)
        return code

    @property
    def _valid_date(self):
        """Check and return a valid query date."""
        date = self._parse_date(self.date)

        if not date:
            exit_after_echo(INVALID_DATE)

        try:
            date = datetime.strptime(date, '%Y%m%d')
        except ValueError:
            exit_after_echo(INVALID_DATE)

        # A valid query date should within 50 days.
        offset = date - datetime.today()
        if offset.days not in range(-1, 50):
            exit_after_echo(INVALID_DATE)

        return datetime.strftime(date, '%Y-%m-%d')

    @staticmethod
    def _parse_date(date):
        """Parse from the user input `date`.

        e.g. current year 2016:
           input 6-26, 626, ... return 2016626
           input 2016-6-26, 2016/6/26, ... retrun 2016626

        This fn wouldn't check the date, it only gather the number as a string.
        """
        result = ''.join(re.findall('\d', date))
        l = len(result)

        # User only input month and day, eg 6-1, 6.26, 0626...
        if l in (2, 3, 4):
            year = str(datetime.today().year)
            return year + result

        # User input full format date, eg 201661, 2016-6-26, 20160626...
        if l in (6, 7, 8):
            return result

        return ''

    def _build_params(self):
        """Have no idea why wrong params order can't get data.
        So, use `OrderedDict` here.
        """
        d = OrderedDict()
        d['purpose_codes'] = 'ADULT'
        d['queryDate'] = self._valid_date
        d['from_station'] = self._from_station_telecode
        d['to_station'] = self._to_station_telecode
        return d

    def query(self):

        params = self._build_params()

        try:
            r = requests.get(QUERY_URL, params=params, verify=False)
        except ConnectionError:
            exit_after_echo(NETWORK_CONNECTION_FAIL)

        try:
            rows = r.json()['data']['datas']
        except KeyError:
            rows = []
        except TypeError:
            exit_after_echo(NO_RESPONSE)

        return TrainsCollection(rows, self.opts)


def query(params):
    """`params` is a list, contains `from`, `to`, `date`."""

    return TrainTicketsQuery(*params).query()


def show_usage():
    """Usage:
    iquery [-dgktz] <from> <to> <date>

Go to `trains -h` for more details.
"""
    pass


def test():
    """Various information query via command line.

Usage:
    query [-dgktz] <from> <to> <date>

Arguments:
    from             出发站
    to               到达站
    date             查询日期

Options:
    -h, --help       显示该帮助菜单.
    -dgktz           动车,高铁,快速,特快,直达

Go to https://github.com/protream/tickets for usage examples.
"""

    if args.is_asking_for_help:
        exit_after_echo(cli.__doc__, color=None)

    elif args.is_querying_train:
        result = query(args.as_train_query_params)

    else:
        exit_after_echo(show_usage.__doc__, color=None)

    result.pretty_print()

if __name__ == '__main__':
    test()
