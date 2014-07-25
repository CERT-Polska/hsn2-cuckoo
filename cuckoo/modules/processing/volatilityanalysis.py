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

log = logging.getLogger(__name__)

MISSING_DEPENDENCIES = []

try:
    import volatility
    import volatility.constants as constants
    import volatility.commands as commands
    import volatility.registry as MemoryRegistry
    import volatility.utils as exceptions
    import volatility.obj as volobj
    import volatility.debug as debug
    import volatility.protos as protos
    import volatility.conf as conf
    import volatility.cache as cache
except ImportError:
    MISSING_DEPENDENCIES.append("volatility 2.0")

try:
    import volatility.plugins.malware as malware
except ImportError as e:
    log.error(e)
    MISSING_DEPENDENCIES.append("malware.py volatility plugin")

try:
    import pefile
except ImportError:
    MISSING_DEPENDENCIES.append("pefile")

try:
    import yara
except ImportError:
    MISSING_DEPENDENCIES.append("yara")

try:
    import distorm3
except ImportError:
    MISSING_DEPENDENCIES.append("distorm3")



if __name__ == "__main__":
    sys.path.append('../../')
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config as CuckooConfig
from lib.cuckoo.common.abstracts import Processing

sys.path.append(os.path.join(CUCKOO_ROOT, 'conf', 'volatility'))
from volatilityprocessorruleloader import VolatilityProcessorRuleLoader as vprl


class VolatilityAnalysis(Processing):
    """Volatility memory dump analysis."""
    volatilityConfig = None
    analysisConfig = None
    rulePath = os.path.join(CUCKOO_ROOT, 'conf', 'volatility')
    params = {
        "rating_whitelist" : 0.5,
        "rating_services" : 0.5,
        "rating_hidden" : 1.5,
        "rating_orphan" : 1.5,
        "rating_api_unknown" : 1.5,
        "rating_api_known" : 0.5,
        "rating_malfind_pe" : 1.5,
        "rating_malfind" : 0.5,
        "none" : 0
    }

    tagToRating = {
        "connected_processes" : "rating_whitelist",
        "running_services" : "rating_services",
        "hidden_processes" : "rating_hidden",
        "orphan_threads" : "rating_orphan",
        "api_hooks_unknown" : "rating_api_unknown",
        "api_hooks_known" : "rating_api_known",
        "malfind_executable" : "rating_malfind_pe",
        "malfind_no_executable" : "rating_malfind",
        "none" : "none"
    }

    rules = {}

    def __init__(self):
        self.volatilityConfig = conf.ConfObject()
        self.volatilityConfig.final = True
        self.volatilityConfig.verbose = False
        
        
        self.key = "volatility_hsn"

    def preConfigure(self):
        '''
        Checks if the plugin dependencies are satisfied.
        Loads the rating configuration and the analysis configuration.
        '''
        if len(MISSING_DEPENDENCIES) > 0:
            log.warning("Dependencies missing: %s, skip" % ','.join(MISSING_DEPENDENCIES))
            return False

        memdumpPath = self.memory_path
        if not os.path.isfile(memdumpPath):
            log.warning("Memory dump '%s' not found for Volatility, skip" % memdumpPath)
            return False
        else:
            self.volatilityConfig.LOCATION = "file://%s" % memdumpPath

        if not self.setExternalParameters():
            return False

        if not self.setVolatilityProfile():
            log.warning("Couldn't determine which volatility profile to use, skip")
            return False
        MemoryRegistry.PluginImporter()
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
            if self.params.get("rating_whitelist", 0) > 0:
                self.rules["connected_processes"] = vprl.loadConnectedProcessesConf(os.path.join(self.rulePath, 'connected_processes.conf'))
            if self.params.get("rating_services", 0) > 0:
                self.rules["running_services"] = vprl.loadRunningServicesConf(os.path.join(self.rulePath, 'running_services.conf'))
            if self.params.get("rating_api_unknown", 0) > 0 or self.params.get("rating_api_known", 0) > 0:
                self.rules["api_hooks"] = vprl.loadApiHooksConf(os.path.join(self.rulePath, 'api_hooks.conf'))
        except Exception as e:
            log.warning("Volatility processor - %s, skip" % str(e))
            return False
        return True

    def run(self):
        """Run volatility processing.
        @return: list with matches.
        """
        matches = { 'connected_processes':None,
                'running_services': None,
                'hidden_processes': None,
                'orphan_threads': None,
                'api_hooks':None,
                'malfind': None
            }

        if not self.preConfigure():
            return {}
        if not self.loadRuleFiles():
            return {}

        log.info("Volatile Systems Volatility Framework {0} - cuckoo processor\n".format(constants.VERSION))
        log.debug(self.params)

        if self.params.get("rating_whitelist", 0) > 0:
            matches['connected_processes'] = self.heuristicConnectedProcesses()
        if self.params.get("rating_services", 0) > 0:
            matches['running_services'] = self.heuristicRunningServices()
        if self.params.get("rating_hidden", 0) > 0:
            matches['hidden_processes'] = self.heuristicHiddenProcesses()
        if self.params.get("rating_orphan", 0) > 0:
            matches['orphan_threads'] = self.heuristicOrphanThreads()
        if self.params.get("rating_api_unknown", 0) > 0 or self.params.get("rating_api_known", 0) > 0:
            matches['api_hooks'] = self.heuristicApiHooks()
        if self.params.get("rating_malfind", 0) > 0 or self.params.get("rating_malfind_pe", 0) > 0:
            matches['malfind'] = self.heuristicMalfind()
        matches = self.combineResultsForPids(matches)
        log.debug(matches)
        return matches

    def setVolatilityProfile(self):
        '''
        Gets called in order to set the profile which will be used when processing the dump file.
        If a profile was supplied and it exists then the profile is set and the function returns.
        If a profile wasn't supplied or it doesn't exist then detection if performed by calling self.detectSystem. 
        @return: True if successfully determined and set the profile and otherwise False.
        '''
        if self.params:
            profile = self.params.get('operating_system')
        else:
            profile = None

        if profile == 'None':
            profile = None

        if profile is not None and MemoryRegistry.PROFILES.objects.get(profile) is None:
            log.warning("Specified profile '%s' not found. Attempting to detect profile." % profile)
            profile = None

        if profile is None:
            profile = self.detectSystem()

        self.volatilityConfig.PROFILE = profile

        if profile is None:
            return False
        return True

    def detectSystem(self):
        '''
        Attempts to identify the profile to use for the supplied dump file.
        Uses the imageinfo command in order to determine the profile.
        @return: True if successfully determined and set the profile and otherwise False.
        '''
        profile = None
        result = self.runModule("imageinfo")
        profileSearch = re.compile(r"(\w+)")
        for line in result:
            if line[0] == "Suggested Profile(s)":
                match = profileSearch.match(line[1])
                break
        if match is not None:
            profile = match.group(1)
            if MemoryRegistry.PROFILES.objects.get(profile) is None:
                profile = None
        return profile

    def splitPath(self, str):
        result = ntpath.split(str)
        if result[0] == str:
            result = path.split(str)
        return result

    def runModule(self, module, method = "calculate"):
        log.debug("Attempting to run %s" % module)
        try:
                log.debug("pre %s" % method)
                command = MemoryRegistry.get_plugin_classes(commands.Command, lower=True)[module](self.volatilityConfig)
                self.volatilityConfig.parse_options()
                if method:
                    log.debug("method %s" % method)
                    return getattr(command, method)()
                else:
                    log.debug("command %s" % method)
                    return command
        except Exception as e:
            log.error(e)

    def runHeuristic(self, gather, filter = None):
        objects = gather()
        log.debug(str(objects))
        if filter:
            objects = filter(objects)
            log.debug(str(objects))
        return objects

    def heuristicConnectedProcesses(self):
        return self.runHeuristic(self.heuristicConnectedProcessesGather, self.heuristicConnectedProcessesFilter)

    def heuristicConnectedProcessesGather(self):
        sockScan = self.runModule('sockscan')
        connScan = self.runModule('connscan')
        objects = {}

        for sock_obj in sockScan:
            obj = {   'pid' : str(sock_obj.Pid),
                      'source port' : str(sock_obj.LocalPort),
                      'source port int' : int(sock_obj.LocalPort),
                      'destination port' : None, # will be overridden by connScan result if found
                      'protocol' : protos.protos.get(sock_obj.Protocol.v(), "-"),
                      'ip' : str(sock_obj.LocalIpAddress)  }
            log.debug("SOCK OBJ - %s" % str(obj))
            if objects.get(obj['pid']) is None:
                 objects[obj['pid']] = {'filename': None, 'path' : None}
            objects[obj['pid']][obj['source port']] = obj

        for tcp_obj in connScan:
            obj = { 'source port' : str(tcp_obj.LocalPort),
                'source port int' : int(tcp_obj.LocalPort),
                'destination port' : int(tcp_obj.RemotePort),
                'remote ip' : str(tcp_obj.RemoteIpAddress),
                'protocol' : 'TCP',
                'ip' : str(tcp_obj.LocalIpAddress),
                'pid' : str(tcp_obj.Pid) }
            log.debug("TCP OBJ - %s" % str(obj))
            if objects.get(obj['pid']) is None:
                objects[obj['pid']] = {'filename': None, 'path' : None}

            if objects[obj['pid']].get(obj['source port']) is None:
                objects[obj['pid']][obj['source port']] = obj
            else:
                objects[obj['pid']][obj['source port']]['destination port'] = obj['destination port']
                objects[obj['pid']][obj['source port']]['remote ip'] = obj['remote ip']

        self.volatilityConfig.PID = ','.join(objects.iterkeys())
        dllList = self.runModule('dlllist')
        for task in dllList:
            pid = str(task.UniqueProcessId)
            filename = task.ImageFileName
            if task.Peb:
                objects[pid]['path'] = str(task.Peb.ProcessParameters.ImagePathName)
            objects[pid]['filename'] = filename
        self.volatilityConfig.PID = None
        return objects

    def heuristicConnectedProcessesFilter(self, objects):
        for rule in self.rules["connected_processes"]:
            for pidObjs in objects:
                if rule['path'] != "*":
                    if objects[pidObjs]['path']:
                        if objects[pidObjs]['path'] != rule['path']:
                            log.debug("%s skipped - diff path %s" % (pidObjs, rule['path']))
                            continue
                    elif rule['filename'] != objects[pidObjs]['filename']:
                         log.debug("%s skipped - diff filename %s" % (pidObjs, rule['filename']))
                         continue
                for obj in objects[pidObjs]:
                    if obj == "path" or obj == "filename":
                        continue
                    if objects[pidObjs][obj] is None:
                        log.debug('%s - %s - object already whitelisted' % (pidObjs, obj))
                        continue
                    if objects[pidObjs][obj]['protocol'] not in ['TCP', 'UDP']:
                        objects[pidObjs][obj] = None
                        continue
                    if objects[pidObjs][obj]['source port int'] < rule['source port'][0] or objects[pidObjs][obj]['source port int'] > rule['source port'][1]:
                        log.debug("%s skipped - diff src port %s" % (pidObjs, rule['source port']))
                        continue
                    if rule['protocol'] != "*" and objects[pidObjs][obj]['protocol'] != rule['protocol']:
                        log.debug("%s skipped - diff protocol %s" % (pidObjs, rule['protocol']))
                        continue
                    if rule['ip'] != "*" and objects[pidObjs][obj]['ip'] != rule['ip']:
                        log.debug("%s skipped - diff ip %s %s" % (pidObjs, objects[pidObjs][obj]['ip'], rule['ip']))
                        continue
                    if objects[pidObjs][obj]['protocol'] != "UDP":
                        if objects[pidObjs][obj]['destination port'] is None:
                            if rule['destination port'] != [0, 65535]:
                                log.debug("%s skipped - no dest port and rule without whole range port %s" % (pidObjs))
                                continue
                        elif objects[pidObjs][obj]['destination port'] < rule['destination port'][0] or objects[pidObjs][obj]['destination port'] > rule['destination port'][1]:
                            log.debug("%s skipped - diff dest port %s - %s" % (pidObjs, objects[pidObjs][obj]['destination port'], rule['destination port']))
                            continue
                    # reached here so deserves to be whitelisted.
                    log.debug("%s %s whitelisted" % (pidObjs, obj))
                    objects[pidObjs][obj] = None
        for pidObjs in objects:
            objects[pidObjs] = { key:val for (key, val) in objects[pidObjs].iteritems() if bool(val) }
        objects = { key:val for (key, val) in objects.iteritems() if len(val) > 2 }
        return objects.keys()

    def heuristicRunningServices(self):
        return self.runHeuristic(self.heuristicRunningServicesGather, self.heuristicRunningServicesFilter)

    def heuristicRunningServicesGather(self):
        svcScan = self.runModule('svcscan')
        objects = {}
        for rec in svcScan:
            Type = '|'.join(malware.get_flags(malware.SERVICE_TYPES, rec.Type))
            State = '|'.join(malware.get_flags(malware.SERVICE_STATES, rec.State))
            if 'SERVICE_KERNEL_DRIVER' in Type or 'SERVICE_FILE_SYSTEM_DRIVER' in Type:
                Binary = malware.wctomb(rec.Binary1, rec.obj_vm)
                ProcId = '-'
            else:
                Binary = malware.wctomb(rec.Binary2.ServicePath, rec.obj_vm)
                ProcId = rec.Binary2.ProcessId
            if Binary is None:
                Binary = '-'
            if ProcId is None or isinstance(ProcId, volobj.NoneObject):
                ProcId = '-'
            obj = {
                   'pid' : str(ProcId),
                   'name' : malware.wctomb(rec.ServiceName, rec.obj_vm),
                   'state' : str(State),
                   'path' : str(Binary),
                }
            log.debug("SVC obj: %s" % str(obj))
            if objects.get(obj['pid']) is None:
                objects[obj['pid']] = []
            objects[obj['pid']].append(obj)
        return objects

    def heuristicRunningServicesFilter(self, objects):
        for rule in self.rules["running_services"]:
            for pidObjs in objects:
                for obj in range(len(objects[pidObjs])):
                    if objects[pidObjs][obj] is None:
                        continue
                    if rule['pid'] != '*' and objects[pidObjs][obj]['pid'] != rule['pid']:
                        log.debug("%s skipped - diff pid %s - %s" % (pidObjs, objects[pidObjs][obj]['pid'], rule['pid']))
                        continue
                    if rule['name'] != '*' and objects[pidObjs][obj]['name'] != rule['name']:
                        log.debug("%s skipped - diff name %s - %s" % (pidObjs, objects[pidObjs][obj]['name'], rule['name']))
                        continue
                    if rule['state'] != '*' and objects[pidObjs][obj]['state'] != rule['state']:
                        log.debug("%s skipped - diff state %s - %s" % (pidObjs, objects[pidObjs][obj]['state'], rule['state']))
                        continue
                    if rule['path'] != '*' and objects[pidObjs][obj]['path'] != rule['path']:
                        log.debug("%s skipped - diff path %s - %s" % (pidObjs, objects[pidObjs][obj]['path'], rule['path']))
                        continue
                    objects[pidObjs][obj] = None
                    log.debug("%s %s whitelisted" % (pidObjs, obj))
        for pidObjs in objects:
            objects[pidObjs] = filter(bool, objects[pidObjs])
        objects = { key:val for (key, val) in objects.iteritems() if bool(val) }
        return objects.keys()

    def heuristicHiddenProcesses(self):
        return self.runHeuristic(self.heuristicHiddenProcessesGather)

    def heuristicHiddenProcessesGather(self):
        psxView = self.runModule('psxview')
        objects = { }
        for offset, process, ps_sources in psxView:
            if not ps_sources['pslist'].has_key(offset) and ps_sources['psscan'].has_key(offset):
                obj = {
                       'pid' : str(process.UniqueProcessId),
                       'name' : str(process.ImageFileName)
                    }
                log.debug("hidden proc: %s" % str(obj))
                objects[obj['pid']] = obj
        return objects

    def heuristicOrphanThreads(self):
        return self.runHeuristic(self.heuristicOrphanThreadsGather)

    def heuristicOrphanThreadsGather(self):
        threads = self.runModule('threads')
        objects = []
        for thread, proc_offset, checks in threads:
            if checks['OrphanThread']:
                objects.append(thread)
        return objects

    def heuristicApiHooks(self):
        return self.runHeuristic(self.heuristicApiHooksGather, self.heuristicApiHooksFilter)

    def heuristicApiHooksGather(self):
        apiHooks = self.runModule('apihooks')
        objects = { }
        unknown = []
        for (proc, type, current_mod, mod, func, src, dst, hooker, instruction) in apiHooks:
            pid = str(proc.UniqueProcessId)
            dest = str(dst)
            if hooker == "UNKNOWN":
                unknown.append(pid)
                continue
            if objects.get(pid) is None:
                 objects[pid] = {}
            if objects[pid].get(hooker) is None:
                objects[pid][hooker] = {}
            objects[pid][hooker][dest] = None
        self.volatilityConfig.PID = ','.join(objects.iterkeys())
        dllListModule = self.runModule('dlllist', None)
        dllListData = dllListModule.calculate()
        dlls = {}
        for task in dllListData:
            pid = str(task.UniqueProcessId)
            for m in dllListModule.list_modules(task):
                long = str(m.FullDllName)
                short = self.splitPath(long)[-1]
                start = int(m.DllBase)
                end = int(m.DllBase + m.SizeOfImage)
                if short in objects[pid]:
                    for dest in objects[pid][short]:
                        destInt = int(dest)
                        if start <= destInt <= end:
                            if dlls.get(long) is None:
                                dlls[long] = []
                            dlls[long].append(pid)
                            objects[pid][short][dest] = long
        self.volatilityConfig.PID = None
        dlls['UNKNOWN'] = unknown
        del objects
        return dlls

    def heuristicApiHooksFilter(self, objects):
        for rule in self.rules["api_hooks"]:
            for dll in objects:
                if rule['path'][-1] in ["\\"]:
                    if rule['path'] == dll[:len(rule['path'])]:
                        objects[dll] = None
                else:
                    if rule['path'] == dll:
                        objects[dll] = None
        objects = { key:val for (key, val) in objects.iteritems() if bool(val) }
        for key in objects:
            objects[key] = set(objects[key])
        return objects

    def heuristicMalfind(self):
        return self.runHeuristic(self.heuristicMalfindGather)

    def heuristicMalfindGather(self):
        self.volatilityConfig.DUMP_DIR = tempfile.gettempdir()
        malFind = self.runModule('malfind')
        objects = {'no_executable':set(), 'executable':set()}
        for (name, pid, start, end, tag, prx, fname, hits, chunk) in malFind:
            try:
                pefile.PE(fname)
            except:
                objects['no_executable'].add(str(pid))
            else:
                objects['executable'].add(str(pid))
            os.remove(fname)
        self.volatilityConfig.DUMP_DIR = None
        return objects

    def addTagToResults(self, results, pidIterable, tag):
        if pidIterable:
            rating = float(self.params.get(self.tagToRating.get(tag, "none")))
            for pid in pidIterable:
                try:
                    results[pid][tag] = rating
                    results[pid]["summed_rating"] += rating
                except KeyError:
                    results[pid] = {tag:rating, "summed_rating":rating}

    def combineResultsForPids(self, matches):
        results = {}
        if matches['orphan_threads']:
            results['-'] = ['orphan_threads']
        self.addTagToResults(results, matches['connected_processes'], 'connected_processes')
        self.addTagToResults(results, matches['running_services'], 'running_services')
        self.addTagToResults(results, matches['hidden_processes'], 'hidden_processes')
        if matches['api_hooks']:
            if 'UNKNOWN' in matches['api_hooks']:
                self.addTagToResults(results, matches['api_hooks']['UNKNOWN'], 'api_hooks_unknown')
            for dll in matches['api_hooks']:
                self.addTagToResults(results, matches['api_hooks'][dll], 'api_hooks_known')
        if matches['malfind']:
            for type in matches['malfind']:
                self.addTagToResults(results, matches['malfind'][type], 'malfind_' + type)
        return results

if __name__ == "__main__":
    logFormatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    consoleHandler = logging.StreamHandler(stream = sys.stderr)
    consoleHandler.setFormatter(logFormatter)
    log.addHandler(consoleHandler)
    log.setLevel(logging.DEBUG)
    vol = VolatilityAnalysis()
    vol.analysis_path = "/home/wojciechm/workspace/"
    vol.conf_path = os.path.join(vol.analysis_path, "analysis.conf")
    vol.run()
