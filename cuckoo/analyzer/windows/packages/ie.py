# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
import base64

class IE(Package):
    """Internet Explorer analysis package."""

    def start(self, path):
        arg = "\"%s\"" % path
        p = Process()
#        p.execute(path="C:\\Program Files\\Internet Explorer\\iexplore.exe", args=arg, suspended=True)
        url = self.options["url"]
        url = url + "=" * (-len(url)%4)
        url = base64.b64decode(url)
        p.execute(path="C:\\Program Files\\Internet Explorer\\iexplore.exe", args=url, suspended=True)
        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
