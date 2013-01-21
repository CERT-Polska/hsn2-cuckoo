#!/usr/bin/python -tt

# Copyright (c) NASK, NCSC
# 
# This file is part of HoneySpider Network 2.0.
# 
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''
Created on 20-07-2012

@author: wojciechm
'''

from lib.common.paths import PATHS
from lib.common.abstracts import Package
from lib.api.process import Process
import time
import shutil
import base64

class IEProcMon(Package):
    """IE analysis with procmon package."""
    procmon = None

    def start(self, path):
        self.procmon = Process()
        p = Process()
        self.procmon.execute(path = "C:\\Procmon\\Procmon.exe", args = "/Quiet /backingfile C:\\procmon", suspended = False)
        self.procmon.execute(path = "C:\\Procmon\\Procmon.exe", args = "/WaitForIdle", suspended = False)

        url = self.options["url"]
        url = url + "=" * (-len(url)%4)
        url = base64.b64decode(url)
        p.execute(path = "C:\\Program Files\\Internet Explorer\\iexplore.exe", args=url, suspended = True)
        p.resume()
        return p.pid

    def check(self):
        return True

    def finish(self):
        self.procmon.execute(path = "C:\\Procmon\\Procmon.exe", args = "/Terminate", suspended = False)
        self.procmon.execute(path = "C:\\Procmon\\Procmon.exe", args = "/PagingFile /NoConnect /Minimized /Quiet", suspended = False)
        time.sleep(15)
        self.procmon.execute(path = "C:\\Procmon\\Procmon.exe", args = "/Terminate", suspended = False)
        self.procmon.execute(path = "C:\\Procmon\\Procmon.exe", args = "/saveas C:\\cuckoo\\procmon.csv /openlog C:\\procmon.PML", suspended = False)
        return True
