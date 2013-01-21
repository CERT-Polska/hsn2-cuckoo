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

import os
import os.path as path
import ntpath
import sys
import logging
import re
import tempfile
import json
import csv

if __name__ == "__main__":
    sys.path.append('../../')
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config as CuckooConfig
from lib.cuckoo.common.abstracts import Processing

sys.path.append(os.path.join(CUCKOO_ROOT, 'conf', 'procmon'))
from procmonprocessorrulelloader import ProcMonProcessorRuleLoader as pprl

log = logging.getLogger(__name__)

class ProcMonAnalysis(Processing):
    """ProcMon CSV log analysis."""
    analysisConfig = None
    csvLog = None
    rulePath = os.path.join(CUCKOO_ROOT, 'conf', 'procmon')
    params = {
        "behavioral_importance" : 1,
        "none" : 0
    }

    rules = {}

    def __init__(self):
        self.key = "procmon"

    def preConfigure(self):
        '''
        Checks if the plugin dependencies are satisfied.
        Loads the rating configuration and the analysis configuration.
        '''
        csvPath = os.path.abspath(os.path.join(self.analysis_path, 'procmon.csv'))
        if not os.path.isfile(csvPath):
            log.warning("Procmon csv log files '%s' not found, skip" % csvPath)
            return False
        else:
            try:
                self.csvLog = csv.reader(open(csvPath, 'rb'))
            except:
                log.warning("Couldn't open csv log file '%s', skip" % csvPath)

        if not self.setExternalParameters():
            return False
        return True

    def setExternalParameters(self):
        '''
        Configures the plugin ratings and any other parameters which were passed.
        Uses two sources - the ratings.conf file and the tasks custom field (dictionary dumped as a json).
        '''
        try:
            self.analysisConfig = CuckooConfig(self.conf_path)
            ratingsConf = CuckooConfig(os.path.join(self.rulePath, "ratings.conf"))
            for rating in ratingsConf.get("ratings").iteritems():
                self.params[rating[0]] = rating[1]
        except Exception as e:
            log.warning("Preconfigure - %s" % str(e))
            return False

        try:
            params = json.loads(self.analysisConfig.get("analysis").get("custom"))
            for param in params.iteritems():
                self.params[param[0]] = param[1]
        except ValueError as e:
            if self.analysisConfig.get("analysis").get("custom") != "None":
                log.warning("Couldn't load json object from custom, skip")
                return False
        return True

    def loadRuleFiles(self):
        try:
            if self.params.get("behavioral_importance", 0) > 0:
                self.rules["procmon"] = pprl.loadProcMonConf(os.path.join(self.rulePath, 'procmon.conf'))
        except Exception as e:
            log.warning("ProcMon processor - %s, skip" % str(e))
            return False
        return True

    def run(self):
        """Run procmon csv processing.
        @return: list with matches.
        """
        matches = {}

        if not self.preConfigure():
            return matches
        if not self.loadRuleFiles():
            return matches

        log.info("Procmon CSV analysis")
        log.debug(self.params)

        if self.params.get("behavioral_importance", 0) > 0:
            matches = self.blacklistProcMon()
        log.debug(matches)
        return matches

    def splitPath(self, str):
        result = ntpath.split(str)
        if result[0] == str:
            result = path.split(str)
        return result

    def blacklistProcMon(self):
        objects = {}
        title = self.csvLog.next()
        multiplier = self.params.get("behavioral_importance", 0)
        for line in self.csvLog:
            for rule in self.rules["procmon"]:
                if line[3] == rule["operation"] and line[4] == rule["path"]:
                    cause = "%s-%s" % (line[3], line[4])
                    try:
                        objects[line[2]]["summed_rating"] += rule["rating"] * multiplier
                        objects[line[2]][cause] += rule["rating"] * multiplier
                    except KeyError:
                        objects[line[2]] = {"summed_rating":rule["rating"] * multiplier, cause:rule["rating"] * multiplier}
        return objects

if __name__ == "__main__":
    logFormatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    consoleHandler = logging.StreamHandler(stream = sys.stderr)
    consoleHandler.setFormatter(logFormatter)
    log.addHandler(consoleHandler)
    log.setLevel(logging.DEBUG)
    pma = ProcMonAnalysis()
    pma.analysis_path = "/home/wojciechm/workspace"
    pma.conf_path = os.path.join(pma.analysis_path, "analysis.conf")
    pma.run()
