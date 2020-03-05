#! /bin/python
#
# Author:       Rafael Tanaka
# Source:       https://github.com/massaox/domain_finder
# Version 1.0

import re
import platform
import fnmatch
import os
import socket
import subprocess
import sys
import array
import struct
import fcntl
import urllib2
import json
import collections
import glob
import codecs
import socket


def stdExceptions(etype, value, tb):
    '''
    The following exits cleanly on Ctrl-C or EPIPE
     while treating other exceptions as before.
    '''
    sys.excepthook = sys.__excepthook__
    if issubclass(etype, KeyboardInterrupt):
        pass
    elif issubclass(etype, IOError) and value.errno == errno.EPIPE:
        pass
    else:
        sys.__excepthook__(etype, value, tb)


sys.excepthook = stdExceptions


class bcolors:
    '''
    Class used for color formatting
    '''
    HEADER = '\033[95m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    PURPLE = '\033[35m'
    LIGHTRED = '\033[91m'
    CYAN = '\033[36m'
    UNDERLINE = '\033[4m'


def getInodePidMap():
    '''
    Create a list of dictionares where the inode listening to connections is
    the key and its pids are the values
    '''
    # glob glob glob it all
    allFDs = glob.iglob("/proc/*/fd/*")
    inodePidMap = collections.defaultdict(list)

    for fd in allFDs:
        # split because path looks like: /proc/[pid]/fd/[number]
        _, _, pid, _, _ = fd.split('/')
        try:
            target = os.readlink(fd)
        except OSError:
            # file vanished, can't do anything else
            continue

        # "target" is now something like:
        #   - socket:[INODE]
        #   - pipe:[INODE]
        #   - /dev/pts/N
        #   - or an actual full file paths
        if target.startswith("socket"):
            ostype, inode = target.split(':')
            # strip brackets from fd string (it looks like: [fd])
            inode = int(inode[1:-1])
            inodePidMap[inode].append(int(pid))
    return inodePidMap


def ipv4(addr):
    """
    Convert /proc IPv4 hex address into standard IPv4 notation.
    """

    addr = int(addr, 16)
    # system native byte order, 4-byte integer
    addr = struct.pack("=L", addr)
    addr = socket.inet_ntop(socket.AF_INET, addr)
    return addr


def ipv6(addr):
    """
    Convert /proc IPv6 hex address into standard IPv6 notation.
    """
    # turn ASCII hex address into binary
    addr = codecs.decode(addr, "hex")
    # unpack into 4 32-bit integers in big endian / network byte order
    addr = struct.unpack('!LLLL', addr)
    # re-pack as 4 32-bit integers in system native byte order
    addr = struct.pack('@IIII', *addr)
    # now we can use standard network APIs to format the address
    addr = socket.inet_ntop(socket.AF_INET6, addr)
    return addr


def populateInodes():
    """
    Get all the inodes that are listening to connections
    along with their IP and port.
    """
    inodes = collections.defaultdict(list)
    for ver in ["tcp", "tcp6"]:
        with open("/proc/net/" + ver, 'r') as proto:
            proto = proto.read().splitlines()
            proto = proto[1:]  # drop header row

            for cxn in proto:
                cxn = cxn.split()

                isListening = cxn[3] == "0A"

                # Right now this is a single-purpose tool so if process is
                # not listening, we avoid further processing of this row.
                if not isListening:
                    continue

                ip, port = cxn[1].split(':')
                if ver == "tcp6":
                    ip = ipv6(ip)
                else:
                    ip = ipv4(ip)

                port = int(port, 16)
                inode = cxn[9]

                inodes[int(inode)] = [ip, port]
    return inodes


def getListeningPorts(inodes, inodePidMap):
    '''
    Filter down the list of inodes to only ones being used by Apache and Nginx
    only and usues their binary as key and port/ip as valueu.
    '''
    listeningPorts = collections.defaultdict(list)
    for inode in inodes:
        if inode in inodePidMap:
            for pid in inodePidMap[inode]:
                try:
                    path = "/proc/" + str(pid) + "/exe"
                    process = os.readlink(path)
                    regex = "(httpd|nginx|apache2)"
                except IndexError:
                    continue
                try:
                    if re.search(regex, process):
                        if inodes[inode] not in listeningPorts[process]:
                            listeningPorts[process].append(inodes[inode])
                        else:
                            pass
                except BaseException:
                    # files can vanish on us at any time (and that's okay!)
                    pass
    return listeningPorts


def getDomain():
    '''
    Function that prompts the user for which domain to look for
    '''
    print(bcolors.PURPLE + "Please enter a domain name " + bcolors.ENDC)
    tty = open('/dev/tty')
    domain = tty.readline().strip()
    tty.close()
    while True:
        if "." not in domain or not len(domain) >= 4:
            print(bcolors.RED + "Enter a valid domain name " + bcolors.ENDC)
            tty = open('/dev/tty')
            domain = tty.readline().strip()
            tty.close()
        else:
            break
    return domain


def outputDns(domain):
    '''
    Function will attempt to use Google's DNS to retrieve A record, if it can't
    it will resort the the Name Servers configured in the server
    '''
    try:
        #site = urllib2.Request("https://dns.google/resolve?name={}&type=A".format(domain))
        site = urllib2.Request("https://dns.google/resolve?name=" + domain + "&type=A")
        response = urllib2.urlopen(site, timeout=5).read()
        resp_json = json.loads(response)
        if resp_json.get('Status') == 0:
            try:
                dns = resp_json['Answer'][0]['data']
                #print("{} points to{} {} {}".format(domain, bcolors.CYAN, dns,
                #bcolors.ENDC))
                print( "The domain points to " + bcolors.CYAN + dns + bcolors.ENDC)
            except (KeyError):
                print("There is no A record for this domain")
        else:
            print("There is no A record for this domain")
    except (socket.timeout):
        get_dns_locally(domain)


def outputDnsLocally(domain):
    '''
    Looks for the "A" record of the domain using the Name Server
    from the server, if DNS doctrine is enabled on the FW you will
     see the private IP of the server
    '''
    try:
        dns = socket.gethostbyname(domain)
        print("{} points to{} {} {}".format(domain, bcolors.CYAN, dns,
        bcolors.ENDC))
        print("==============================")
    except (socket.gaierror, UnboundLocalError):
        print("There is no A record for this domain")


def getLogDir(varname):
    '''
    Open a bash process to extract the log
    location on Ubuntu/Debian installations
    '''
    CMD = 'echo $(source /etc/apache2/envvars; echo $%s)' % varname
    p = subprocess.Popen(
        CMD, stdout=subprocess.PIPE, shell=True, executable='/bin/bash')
    log_path = str(p.stdout.readlines()[0].strip())
    return log_path


def getOs(op_sys=str(platform.linux_distribution())):
    '''
    Block to determine if its Ubuntu or RedHat
    installation using the platform module
    '''
    apacheIncludeFiles = []
    nginxIncludeFiles = []
    if re.search("Red Hat|CentOS", op_sys):
        if os.path.isfile("/etc/httpd/conf/httpd.conf"):
            apache = "/etc/httpd/conf/httpd.conf"
            apacheIncludeFiles.append(apache)
            isApache = True
        else:
            isApache = False
            apache = ""
        if os.path.isfile("/etc/nginx/nginx.conf"):
            nginx = "/etc/nginx/nginx.conf"
            nginxIncludeFiles.append(nginx)
            isNginx = True
        else:
            isNginx = False
            nginx = ""
    elif re.search("Ubuntu|Debian", op_sys):
        if os.path.isfile("/etc/apache2/apache2.conf"):
            apache = "/etc/apache2/apache2.conf"
            apacheIncludeFiles.append(apache)
            isApache = True
        else:
            isApache = False
            apache = ""
        if os.path.isfile("/etc/nginx/nginx.conf"):
            nginx = "/etc/nginx/nginx.conf"
            nginxIncludeFiles.append(nginx)
            isNginx = True
        else:
            isNginx = False
            nginx = ""
    return apache, isApache, apacheIncludeFiles, nginx, isNginx, nginxIncludeFiles


def getApacheRoot(apache):
    '''
    Retrieves Apache's document root to be used later if relative log path is
    used.
    '''
    with open(apache, "rt") as config:
        for line in config:
            if re.match("(#)?ServerRoot", line):
                value = line.split()
                apacheRoot = (value[1]).strip("\"\'")
    return apacheRoot


def apacheFindFiles(directory, regex, apacheRoot, apacheIncludeFiles,
                      apacheIncludeDir):
    '''
    Grabs all files from a directory that matches a regex passed
    from the function "getApacheInclude", at the end of
    its execution will call out function "getApacheInclude"
   '''
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            if fnmatch.fnmatch(name, regex):
                full_path = os.path.join(root, name)
                apacheIncludeFiles.append(full_path)
                getApacheInclude(full_path, apacheRoot, apacheIncludeFiles,
                                   apacheIncludeDir)


def getApacheInclude(conf, apacheRoot, apacheIncludeFiles,
                       apacheIncludeDir):
    '''
    Search every line of a given file and grabs the argument for
    Include/IncludeOptional directive, if the argument is a file
    will append to the "apacheIncludeFiles" then call itself one
    more time if the file was not on the "apacheIncludeFiles" list
    and if it finds a directory will call the function "apacheFindFiles"
    '''
    ret = str(conf)
    clean = ret.strip('\"[\', \']\"')
    with open(clean, "rt") as config:
        for line in config:
            no_white = line.strip()
            if re.match("Include", no_white):
                value = no_white.split()
                noquotes = (value[1])
                include = noquotes.strip("\"\'")
                if include.startswith("/"):
                    if os.path.isfile(
                            include) and include not in apacheIncludeFiles:
                        apacheIncludeFiles.append(include)
                        getApacheInclude(include, apacheRoot,
                                           apacheIncludeFiles,
                                           apacheIncludeDir)
                    elif os.path.isdir(include):
                        apacheIncludeDir.append(include)
                        regex = "*"
                        if include not in apacheIncludeDir:
                            apacheFindFiles(include, regex, apacheRoot,
                                              apacheIncludeFiles,
                                              apacheIncludeDir)
                    elif not os.path.isdir(include):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = include.replace(regex, "")
                            if sanitized not in apacheIncludeDir:
                                apacheFindFiles(sanitized,
                                                  regex, apacheRoot,
                                                  apacheIncludeFiles,
                                                  apacheIncludeDir)
                else:
                    full_path = apacheRoot.strip('\"') + "/" + include
                    if os.path.isfile(
                            full_path) and include not in apacheIncludeFiles:
                        apacheIncludeFiles.append(full_path)
                        getApacheInclude(full_path, apacheRoot,
                                           apacheIncludeFiles,
                                           apacheIncludeDir)
                    elif os.path.isdir(full_path):
                        regex = "*"
                        if full_path not in apacheIncludeDir:
                            apacheFindFiles(full_path,
                                              regex, apacheRoot,
                                              apacheIncludeFiles,
                                              apacheIncludeDir)
                    elif not os.path.isdir(full_path):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = full_path.replace(regex, "")
                            if sanitized not in apacheIncludeDir:
                                apacheFindFiles(sanitized, regex,
                                                  apacheRoot, apacheIncludeFiles,
                                                  apacheIncludeDir)
    return apacheIncludeFiles


def apacheFullPathLog(argument, apacheRoot):
    '''
    Function merely created for copy and paste ease,
    it will display the full path to the logs, rather then the relative one.
    '''
    full_log = ""
    if argument.startswith("$"):
        log_path = getLogDir('APACHE_LOG_DIR')
        log_file = argument.split('/')[-1]
        full_log = log_path + "/" + log_file
    elif not argument.startswith("/"):
        full_log = apacheRoot + "/" + argument
    else:
        full_log = argument
    return full_log


def apacheDomainSearch(apacheIncludeFiles, domain):
    '''
    Once the list "apacheIncludeFiles" is populated
    this function goes over each file and looks for the domain in question
    '''
    vhosts = []
    for file in apacheIncludeFiles:
        with open(file, "rt") as vhost:
            for line in vhost:
                no_white = line.strip()
                regex = "^\"?Server(Name|Alias)\"?.*" + domain + ".*"
                if re.search(regex, no_white):
                    vhosts.append(file)
                    break
    return vhosts


def sanitizeArgs(argument):
    '''
    Strips down all single and double quotes from lines
    '''
    sanitized = []
    for line in argument:
        clean = line.split(":")[0].strip('"\'')
        sanitized.append(clean)
    return sanitized


def apacheDirectiveFinder(vhosts_file, apacheRoot):
    '''
    Goes  over the select file(s) and returns only the relevant directives
    '''
    i = 0
    directives = []
    vhosts = {}
    try:
        with open(vhosts_file, "rt") as vhost:
            for line in vhost:
                no_white = line.strip()
                if re.match("<VirtualHost", no_white):
                    d1 = {}
                    line_directive = no_white.split()
                    d1[line_directive[0]] = line_directive[1]
                    directives.append(d1)
                    d1[".Vhost file"] = vhosts_file
                elif re.match(
                        "^(\"|')?ServerName|^(\"|')?DocumentRoot", no_white):
                    try:
                        vhost = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split(
                        )[1].strip('"\'').split(":")[0]
                        vhost[directive] = argument
                    except BaseException:
                        pass
                elif re.match("^(\"|')?CustomLog|^(\"|')?ErrorLog", no_white):
                    try:
                        vhost = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split(
                        )[1].strip('"\'').split(":")[0]
                        full_log = apacheFullPathLog(argument, apacheRoot)
                        vhost[directive] = full_log
                    except BaseException:
                        pass
                elif re.match("^(\"|')?Include|^(\"|')?SSLEngine", no_white):
                    try:
                        vhost = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split(
                        )[1].strip('"\'').split(":")[0]
                        vhost[directive] = argument
                    except BaseException:
                        pass
                elif re.match("^(\"|')?ServerAlias", no_white):
                    vhost = directives[i]
                    if "ServerAlias" not in vhost:
                        directive = no_white.split()[0].strip('"\'')
                        no_white_list = no_white.split()
                        no_white_list.pop(0)
                        argument = no_white_list
                        sanitized = sanitizeArgs(argument)
                        vhost[directive] = sanitized
                    else:
                        directive = no_white.split()[0].strip('"\'')
                        no_white_list = no_white.split()
                        no_white_list.pop(0)
                        argument = no_white_list
                        sanitized = sanitizeArgs(argument)
                        vhost["ServerAlias"] += sanitized
                elif re.match("</VirtualHost", no_white):
                    i += 1
    except (TypeError):
        pass
    return directives


def vhostsFilesParser(vhostsFiles, apacheRoot):
    '''
    Goes over all the config files where the domain is
    mentioned and call the function to extract the main directives
    '''
    vhostsDirectives = []
    if len(vhostsFiles) == 0:
        print("No " + bcolors.YELLOW + "Apache" + bcolors.ENDC
              + " vhosts found for the domain")
    for vhost_file in vhostsFiles:
        vhostsDirectives.extend(apacheDirectiveFinder
                                (vhost_file, apacheRoot))
    return vhostsDirectives


def vhostOrganizer(vhostsDirectives, domain):
    '''
    Takes all the individual vhosts extract from previous function and
    removes all that does contain the "domain " in ServerName or ServerAlis
    '''
    vhosts = []
    for vhost_entry in vhostsDirectives:
        for k, v in vhost_entry.items():
            if domain == v:
                vhosts.append(vhost_entry)
            elif 'ServerAlias' == k:
                for alias in v:
                    if domain == alias:
                        vhosts.append(vhost_entry)
    return vhosts


def apacheWarnInclude(vhosts):
    if 'Include' in vhosts:
        print("include in the vhost, some directives might be overwritten")
    return vhosts


def apacheDefaultLog(vhosts):
    for vhost in vhosts:
        if 'SSLEngine' in vhost:
            if 'CustomLog' not in vhost:
                vhost['CustomLog'] = "/var/log/httpd/ssl-access_log"
            if 'ErrorLog' not in vhost:
                vhost['ErrorLog'] = "/var/log/httpd/ssl-error_log"
        else:
            if 'CustomLog' not in vhost:
                vhost['CustomLog'] = "/var/log/httpd/access_log"
            if 'ErrorLog' not in vhost:
                vhost['ErrorLog'] = "/var/log/httpd/error_log"
    return vhosts


def nginxFindFiles(directory, regex, nginxIncludeFiles, nginxIncludeDir):
    '''
    Grabs all files from a directory that matches a regex passed
    from the function "getNginxInclude", at the end of its
    execution will call out function "getNginxInclude"
   '''
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            if fnmatch.fnmatch(name, regex):
                full_path = os.path.join(root, name)
                nginxIncludeFiles.append(full_path)
                getNginxInclude(full_path, nginxIncludeFiles,
                                  nginxIncludeDir)


def getNginxInclude(conf, nginxIncludeFiles, nginxIncludeDir):
    '''
    Search every line of a given file and grabs the argument for
    include/includeOptional directive, if the argument is a file
    will append to the "nginxIncludeFiles" then call itsefl one
    more time if the file was not on the "nginxIncludeFiles" list
    and if it finds a directory will call the function "nginxFindFiles"
    '''
    ret = str(conf)
    clean = ret.strip('\"[\', \']\"')
    with open(clean, "rt") as config:
        for line in config:
            no_white = line.strip()
            if re.match("include", no_white):
                value = no_white.split()
                noquotes = (value[1])
                include = noquotes.strip("\"\';")
                if include.startswith("/"):
                    if os.path.isfile(include):
                        if include not in nginxIncludeFiles:
                            nginxIncludeFiles.append(include)
                            getNginxInclude(include, nginxIncludeFiles,
                                              nginxIncludeDir)
                    elif os.path.isdir(include):
                        regex = "*"
                        if include not in nginxIncludeDir:
                            nginxFindFiles(include, regex, nginxIncludeFiles,
                                             nginxIncludeDir)
                    elif not os.path.isdir(include):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = include.replace(regex, "")
                            if sanitized not in nginxIncludeDir:
                                nginxFindFiles(
                                    sanitized, regex, nginxIncludeFiles,
                                    nginxIncludeDir)
                else:
                    full_path = "/etc/nginx/" + include
                    if os.path.isfile(full_path):
                        if include not in nginxIncludeFiles:
                            nginxIncludeFiles.append(full_path)
                            getNginxInclude(full_path, nginxIncludeFiles,
                                              nginxIncludeDir)
                    elif os.path.isdir(full_path):
                        regex = "*"
                        if full_path not in nginxIncludeDir:
                            nginxFindFiles(
                                full_path, regex, nginxIncludeFiles,
                                nginxIncludeDir)
                    elif not os.path.isdir(full_path):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = full_path.replace(regex, "")
                            if sanitized not in nginxIncludeDir:
                                nginxFindFiles(
                                    sanitized, regex, nginxIncludeFiles,
                                    nginxIncludeDir)
    return nginxIncludeFiles


def sanitizeArgs(argument):
    '''
    Strips down all single and double quotes from lines
    '''
    sanitized = []
    for line in argument:
        clean = line.split(":")[0].strip('"\';')
        sanitized.append(clean)
    return sanitized


def nginxFullPathInclude(argument):
    '''
    Function merely created for copy and paste ease, it will display
    the full path to the include, rather then the relative one.
    '''
    full_path = ""
    if not argument.startswith("/"):
        full_path = "/etc/nginx/" + argument
    else:
        full_path = argument
    return full_path

def findBlocks(nginxIncludeFiles):
    serverBlocks = []
    close_brackets = False
    server_arg = False
    inside_block = False
    inside_location = False
    location_arg = False
    open_count = 0
    close_count = 0
    for file in nginxIncludeFiles:
        try:
            with open(file, "rt") as config:
                for line in config:
                    no_white = line.strip()
                    no_white = no_white.strip(';')
                    if no_white.startswith('#') or not no_white.strip() or no_white.startswith('type'):
                        pass
                    else:
                        if re.match(r"server($|\s*{)", no_white):
                            block = {}
                            server_arg = True
                            if '{' in no_white:
                                inside_block = True
                        if re.match(r"location", no_white):
                            location_arg = True
                            if '{' in no_white:
                                inside_location = True
                        if inside_location:
                            if '}' in no_white:
                                inside_location = False
                                location_arg = False
                        if inside_block and not inside_location:  
                            if '{' in no_white:
                                open_count += 1
                            elif '}' in no_white:
                                close_count += 1
                                if open_count == close_count:
                                    block[no_white.split()[0]] = no_white.split()[1:]
                                    inside_block = False
                                    config = []
                                    config.append(file)
                                    block["config file"] = config
                                    serverBlocks.append(block)
                                    server_arg = False
                                    block = {}
                            if no_white.split()[0] in block:
                                for item in no_white.split()[1:]:
                                    block[no_white.split()[0]].append(item)
                            else:
                                block[no_white.split()[0]] = no_white.split()[1:]
        except (IOError):
            pass                        
    return serverBlocks                    


def getInclude(serverBlocks):
    for server_block in serverBlocks:
        if "include" in server_block:
            file =  str(server_block["include"])
            file = file.strip('[]\'')
            try:
                with open (file, "rt") as config:
                    for line in config:
                        no_white = line.strip()
                        no_white = no_white.strip(';')
                        if no_white.startswith('#') or not bool(no_white.strip()):
                            pass
                        else:
                            server_block[no_white.split()[0]] = no_white.split()[1:]
            except (IOError):
                pass
    return serverBlocks
	

def findDomain(serverBlocks,domain):
    block = []
    for server_block in serverBlocks:
        for key in server_block:
            if domain  in server_block[key]:
                block.append(dict(server_block))
    return block



def outputPortIp(listeningPorts):
    apache = "(httpd|apache)"
    nginx = "(nginx)"
    for k in listeningPorts:
        if re.search(apache, str(k)):
            print("==============================")
            print(bcolors.YELLOW + "Apache " + bcolors.ENDC +
                  "is listening on %s" % listeningPorts[k])
            print("==============================")
        elif re.search(nginx, str(k)):
            print("==============================")
            print(bcolors.GREEN + "Nginx " + bcolors.ENDC +
                  "is listening on %s" % listeningPorts[k])
            print("==============================")


def vhostIncludeWarning(vhosts):
    for vhost in vhosts:
            if "Include" in vhost:
                    print( bcolors.CYAN + "Include  " + bcolors.ENDC + "detected on the vhost, please look at the file for further configurations")


def outputApache(vhosts):
    for entry in vhosts:
        print("==============================")
        for k in sorted(entry.keys()):
            if k == '.Vhost file':
                print(bcolors.YELLOW + '%15s' % "Vhost File" + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == '<VirtualHost':
                print(bcolors.LIGHTRED + '%15s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == 'ServerName':
                print(bcolors.LIGHTRED + '%15s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == 'Include':
                print(bcolors.CYAN + '%15s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
            else:
                print(bcolors.LIGHTRED + '%15s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
    print("==============================")
    #print("==============================")


def blockIncludeWarning(blocks):
    for block in blocks:
	    if "include" in block:
                    print("")
		    print( bcolors.CYAN + "include  " + bcolors.ENDC + "detected on the block, please look at the file for further configurations")
                    print("")

def replaceRoot(blocks):
    root = ""
    rootVar = ""
    for block in blocks:
        for dir in block:
            if dir == "set":
                rootPath =  block[dir][1]
                rootVar = block[dir][0]
            if dir == "root":
                if not os.path.exists(block[dir][0].strip('\"')):
                    root = block[dir][0]
                    root = root.replace(rootVar, rootPath)
                    newRoot = []
                    newRoot.append(root)
                    block['root'] = newRoot
    return blocks

def findRootVar(root):
    print root        

def OutputNginx(blocks):
    nginxArgs = ['config file', 'server_name', 'root', 'access_log', 'error_log', 'listen', 'ssl_certificate', 'ssl_certificate_key']
    for block in blocks:
        print("==============================")
        for arg in nginxArgs:
            try:
                if arg == "config file":
                    print(bcolors.GREEN + '%15s' % str(arg) + ": "  + bcolors.ENDC + str(block[arg]))
                else:
                    print(bcolors.LIGHTRED + '%15s' % str(arg) + ": "  + bcolors.ENDC + str(block[arg]))
            except (KeyError):
                pass
    print("==============================")
    print("==============================")
    return None


def main():
    apacheIncludeDir = []
    isApache = False
    isNginx = False
    nginxIncludeDir = []

    domain = getDomain()
    outputDns(domain)
    apache, isApache, apacheIncludeFiles, nginx, isNginx, nginxIncludeFiles = getOs()
    inodePidMap = getInodePidMap()
    inodes = populateInodes()
    listeningPorts = getListeningPorts(inodes, inodePidMap)
    portOutput = outputPortIp(listeningPorts)

    if isApache:
        apacheRoot = getApacheRoot(apache)
        apacheIncludeFiles = getApacheInclude(apache, apacheRoot,
                                                apacheIncludeFiles,
                                                apacheIncludeDir)
        vhostsFiles = apacheDomainSearch(apacheIncludeFiles, domain)
        vhostsDirectives = vhostsFilesParser(vhostsFiles, apacheRoot)
        vhosts = vhostOrganizer(vhostsDirectives, domain)
        apacheWarnInclude(vhosts)
        apacheDefaultLog(vhosts)
        vhostIncludeWarning(vhosts)
        outputApache(vhosts)
    if isNginx:
        nginxIncludeFiles = getNginxInclude(nginx, nginxIncludeFiles,
                                              nginxIncludeDir)
        serverBlocks = findBlocks(nginxIncludeFiles)
        serverBlocks = getInclude(serverBlocks)
        blocks = findDomain(serverBlocks,domain)
        blocks = replaceRoot(blocks)
        OutputNginx(blocks)


if __name__ == "__main__":
    main()

