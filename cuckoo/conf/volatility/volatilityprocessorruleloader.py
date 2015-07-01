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

import re
import os
import sys


class ParameterException(Exception):
    pass


class VolatilityProcessorRuleLoader:
    regexps = {}  # used by class methods

    @staticmethod
    def toRating(val):
        try:
            val = round(float(line[0]), 2)
        except Exception as e:
            raise ParameterException("Invalid value in line %d - Exception %s" % (lineno, str(e)))
        if -21474835 < val < 21474835:
            return val
        else:
            raise ParameterException("Invalid rating value in line %d" % (lineno))

    @staticmethod
    def toPortList(ports, lineno=0):
        ports = ports.split('-')
        ports = [int(p) for p in ports]
        for port in ports:
            if port < 0 or port > 65535:
                raise ParameterException("Invalid port in line %d" % lineno)
        if len(ports) == 1:
            ports.append(ports[0])
        return ports

    @classmethod
    def connectedProcessLine(cls, line, lineno=0):
        '''
        Processes a 'connected processes' configuration entry into a valid configuration rule.
        If an invalid entry is found then a ParameterException is raised.
        @param line: The list with the arguments found in the configuration entry.
        @param lineno: The line number at which the entry resides in the configuration file.
        @return: Dictionary containing the rule.
        '''
        if len(line) < 4 or len(line) > 5:
            raise ParameterException("Invalid configuration entry in line %d" % lineno)

        portRegexp = cls.regexps.get('portRegexp')
        ipRegexp = cls.regexps.get('ipRegexp')
        protoList = cls.regexps.get('protoList')

        if portRegexp is None:
            portRegexp = re.compile(r"^((\d+(-\d+)?)|\*)$")
            cls.regexps['portRegexp'] = portRegexp
        if ipRegexp is None:
            ipRegexp = re.compile(r"^(((\d{1,3}.){3,3}(\d{1,3}))|\*)$")
            cls.regexps['ipRegexp'] = ipRegexp
        if protoList is None:
            protoList = ["TCP", "UDP", "*"]
            cls.regexps['protoList'] = protoList

        rule = {'path': line[0],
                'filename': os.path.split(line[0])[1],
                'protocol': line[1].upper(),
                'source port': line[2],
                'ip': line[3]}

        if len(line) > 4:
            rule["destination port"] = line[4]
        else:
            rule["destination port"] = ""

        if rule.get('source port') == "*":
            rule['source port'] = '0-65535'

        if rule.get('destination port') == "*":
            rule['destination port'] = '0-65535'

        if rule['protocol'] not in protoList:
            raise ParameterException("Invalid protocol in line %d" % lineno)

        match = portRegexp.match(rule['source port'])
        if match is None:
            raise ParameterException("Invalid source port in line %d" % lineno)
        else:
            rule["source port"] = VolatilityProcessorRuleLoader.toPortList(match.group(0), lineno)
        if not ipRegexp.match(rule['ip']):
            raise ParameterException("Invalid ip address in line %d" % lineno)

        match = portRegexp.match(rule['destination port'])
        if match is None:
            if not (rule['protocol'] == "UDP" and rule["destination port"] == ''):
                raise ParameterException("Invalid destination port in line %d" % lineno)
        else:
            rule["destination port"] = VolatilityProcessorRuleLoader.toPortList(match.group(0), lineno)

        return rule

    @classmethod
    def runningServicesLine(cls, line, lineno=0):
        '''
        Processes a 'running services' configuration entry into a valid configuration rule.
        If an invalid entry is found then a ParameterException is raised.
        @param line: The list with the arguments found in the configuration entry.
        @param lineno: The line number at which the entry resides in the configuration file.
        @return: Dictionary containing the rule.
        '''
        if len(line) != 4:
            raise ParameterException("Invalid configuration entry in line %d" % lineno)

        pidRegexp = cls.regexps.get('pidRegexp')
        serviceStateList = cls.regexps.get('serviceStateList')

        if pidRegexp is None:
            pidRegexp = re.compile(r"^((\d+(-\d+)?)|\*|-)$")
            cls.regexps['pidRegexp'] = pidRegexp

        if serviceStateList is None:
            serviceStateList = [
                'SERVICE_STOPPED',
                'SERVICE_START_PENDING',
                'SERVICE_STOP_PENDING',
                'SERVICE_RUNNING',
                'SERVICE_CONTINUE_PENDING',
                'SERVICE_PAUSE_PENDING',
                'SERVICE_PAUSED',
                '*']
            cls.regexps['serviceStateList'] = serviceStateList

        rule = {'pid': line[0],
                'name': line[1],
                'state': line[2].upper(),
                'path': ' '.join(line[3:])}

        if not pidRegexp.match(rule['pid']):
            raise ParameterException("Invalid pid in line %d" % lineno)
        if rule['state'] not in serviceStateList:
            raise ParameterException("Invalid state in line %d" % lineno)

        return rule

    @classmethod
    def apiHooksLine(cls, line, lineno=0):
        '''
        Processes a 'api hooks' configuration entry into a valid configuration rule.
        If an invalid entry is found then a ParameterException is raised.
        @param line: The list with the arguments found in the configuration entry.
        @param lineno: The line number at which the entry resides in the configuration file.
        @return: Dictionary containing the rule.
        '''
        if len(line) != 1:
            raise ParameterException("Invalid configuration entry in line %d" % lineno)
        rule = {'path': line[0]}
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
    def loadConnectedProcessesConf(cls, filePath):
        '''
        Shortcut for calling the load method with verifier=cls.connectedProcessLine
        @param filePath: The file path to pass to the load method.
        @return: Whatever the load method returns.
        '''
        return cls.load(filePath, cls.connectedProcessLine)

    @classmethod
    def loadRunningServicesConf(cls, filePath):
        '''
        Shortcut for calling load with verifier=cls.runningServicesLine
        @param filePath: The file path to pass to the load method.
        @return: Whatever the load method returns.
        '''
        return cls.load(filePath, cls.runningServicesLine)

    @classmethod
    def loadApiHooksConf(cls, filePath):
        '''
        Shortcut for calling load with verifier=cls.apiHooksLine
        @param filePath: The file path to pass to the load method.
        @return: Whatever the load method returns.
        '''
        return cls.load(filePath, cls.apiHooksLine)

if __name__ == "__main__":
    try:
        import argparse
    except ImportError:
        print 'argparse module not found. Install to use command line checker.'
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description='Cuckoo volatility processor - configuration checker.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('type', help='type of configuration to check', choices=['connected_processes', 'running_services', 'api_hooks'])
    parser.add_argument('file', help='path to the configuration file')
    args = parser.parse_args()
    verifiers = {
        'connected_processes': VolatilityProcessorRuleLoader.connectedProcessLine,
        'running_services': VolatilityProcessorRuleLoader.runningServicesLine,
        'api_hooks': VolatilityProcessorRuleLoader.apiHooksLine
    }
    vtype = verifiers.get(args.type)
    try:
        results = VolatilityProcessorRuleLoader.load(filePath=args.file, verifier=vtype)
        print "Number of rules loaded: %d." % len(results)
        for result in results:
            print 'rule:', result
    except Exception as e:
        print "Exception: ", e
