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

import re
import os
import sys

class ParameterException(Exception):
    pass

class ProcMonProcessorRuleLoader:
    regexps = {}

    @staticmethod
    def toRating(val, lineno):
        try:
            val = round(float(val), 2)
        except Exception as e:
            raise ParameterException("Invalid value in line %d - Exception %s" % (lineno, str(e)))
        if -21474835 < val < 21474835:
            return val
        else:
            raise ParameterException("Invalid rating value in line %d" % (lineno))

    @classmethod
    def procmonLine(cls, line, lineno = 0):
        '''
        Processes a 'procmon' configuration entry into a valid configuration rule.
        If an invalid entry is found then a ParameterException is raised. 
        @param line: The list with the arguments found in the configuration entry.
        @param lineno: The line number at which the entry resides in the configuration file.
        @return: Dictionary containing the rule.
        '''
        if len(line) != 3:
            raise ParameterException("Invalid configuration entry in line %d" % lineno)
        rule = {'rating' : cls.toRating(line[0], lineno),
                'operation' : line[1],
                'path' : line[2]
            }
        return rule

    @classmethod
    def load(cls, filePath, verifier):
        '''
        Reads lines from a configuration file and passes them on the a specified verifier.
        @param filePath: The path to the configuration file.
        @param verifier: The function to run on each line.
        @return: List of dictionaries. Each dictionary is a rule loaded from a configuration line.
        '''
        fileH = open(filePath)
        rules = []
        i = 0
        for line in fileH:
            i = i + 1
            if line[0] == "#":
                continue
            line = filter(bool, line.rstrip().split("\t"))
            if line:
                rule = verifier(line, i)
                rules.append(rule)
        return rules

    @classmethod
    def loadProcMonConf(cls, filePath):
        '''
        Shortcut for calling load with verifier=cls.apiHooksLine
        @param filePath: The file path to pass to the load method.
        @return: Whatever the load method returns.
        '''
        return cls.load(filePath, cls.procmonLine)

if __name__ == "__main__":
    try:
        import argparse
    except ImportError:
        print 'argparse module not found. Install to use command line checker.'
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description = 'Cuckoo procmon processor - configuration checker.',
        formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('file', help = 'path to the configuration file')
    args = parser.parse_args()
    vtype = ProcMonProcessorRuleLoader.procmonLine
    try:
        results = ProcMonProcessorRuleLoader.load(filePath = args.file, verifier = vtype)
        print "Number of rules loaded: %d." % len(results)
        for result in results:
            print 'rule:', result
    except Exception as e:
        print "Exception: ", e
