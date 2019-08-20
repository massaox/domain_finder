#! /bin/python
#
# Author:       Rafael Tanaka
# Source:       https://github.com/massaox/vhost_finder
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


SERVER_ROOT = ""
APACHE_INCLUDE_DIR = []
APACHE_INCLUDE_FILES = []
IS_APACHE = False
IS_NGINX = False
NGINX_INCLUDE_DIR = []
NGINX_INCLUDE_FILES = []


# The following exits cleanly on Ctrl-C or EPIPE
# while treating other exceptions as before.
def std_exceptions(etype, value, tb):
    sys.excepthook = sys.__excepthook__
    if issubclass(etype, KeyboardInterrupt):
        pass
    elif issubclass(etype, IOError) and value.errno == errno.EPIPE:
        pass
    else:
        sys.__excepthook__(etype, value, tb)
sys.excepthook = std_exceptions


class bcolors:
    '''
    Class used for colour formatting
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

def get_inodePidMap():
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
    """ Convert /proc IPv4 hex address into standard IPv4 notation. """

    addr = int(addr, 16)
    # system native byte order, 4-byte integer
    addr = struct.pack("=L", addr)
    addr = socket.inet_ntop(socket.AF_INET, addr)
    return addr


def ipv6(addr):
    """ Convert /proc IPv6 hex address into standard IPv6 notation. """
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
    """ Get all the inodes that are listening to connections
        along with their IP and port and place

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

def get_listeningPorts(inodes, inodePidMap):
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

def get_portOutput(listeningPorts):
    apache = "(httpd|apache)"
    nginx = "(nginx)"
    for k in listeningPorts:
        if re.search(apache, str(k)):
            webserver = "apache"
            print("==============================")
            print(bcolors.YELLOW + "apache " + bcolors.ENDC +  "is listening on %s"
                  % listeningPorts[k])
        elif re.search(nginx, str(k)):
            print("==============================")
            print(bcolors.GREEN + "nginx " + bcolors.ENDC + "is listening on %s"
                  % listeningPorts[k])


def get_domain():
    ''' Function that prompts the user for which domain to look for
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


def get_dns(domain):
    site = urllib2.Request("https://dns.google/resolve?name=" + domain + "&type=A")
    response = urllib2.urlopen(site, timeout=5).read()
    resp_json = json.loads(response)
    try:
        dns = resp_json['Answer'][0]['data']
        print (domain + " points to " + bcolors.CYAN + dns + bcolors.ENDC)
    except (KeyError):
        print("There is no A record for this domain")
    return domain

#def get_dns(domain):
#    '''
#    Looks for the "A" record of the domain using the Name Server
#    from the server, if DNS doctrine is enabled on the FW you will
#     see the private IP of the server
#    '''
#    try:
#        dns = socket.gethostbyname(domain)
#        print (domain + " points to " + bcolors.CYAN + dns + bcolors.ENDC)
#        print("==============================")
#    except (socket.gaierror, UnboundLocalError):
#        print("There is no A record for this domain")
#    return domain


def get_log_dir(varname):
    '''
    Open a bash process to extract the log
    location on Ubuntu/Debian installations
    '''
    CMD = 'echo $(source /etc/apache2/envvars; echo $%s)' % varname
    p = subprocess.Popen(
        CMD, stdout=subprocess.PIPE, shell=True, executable='/bin/bash')
    log_path = str(p.stdout.readlines()[0].strip())
    return log_path


def os_finder(op_sys=str(platform.linux_distribution())):
    '''
    Block to determine if its Ubuntu or RedHat
    installation using the platform module
    '''
    if re.search("Red Hat|CentOS", op_sys):
        if os.path.isfile("/etc/httpd/conf/httpd.conf"):
            apache = "/etc/httpd/conf/httpd.conf"
            APACHE_INCLUDE_FILES.append(apache)
            IS_APACHE = True
        else:
            IS_APACHE = False
            apache = ""
        if os.path.isfile("/etc/nginx/nginx.conf"):
            nginx = "/etc/nginx/nginx.conf"
            NGINX_INCLUDE_FILES.append(nginx)
            IS_NGINX = True
        else:
            IS_NGINX = False
            nginx = ""
    elif re.search("Ubuntu|Debian", op_sys):
        if os.path.isfile("/etc/apache2/apache2.conf"):
            apache = "/etc/apache2/apache2.conf"
            APACHE_INCLUDE_FILES.append(apache)
            IS_APACHE = True
        else:
            IS_APACHE = False
            apache = ""
        if os.path.isfile("/etc/nginx/nginx.conf"):
            nginx = "/etc/nginx/nginx.conf"
            NGINX_INCLUDE_FILES.append(nginx)
            IS_NGINX = True
        else:
            IS_NGINX = False
            nginx = ""
    return apache, IS_APACHE, nginx, IS_NGINX


def apache_root_finder(apache):
    with open(apache, "rt") as config:
        for line in config:
            if re.match("(#)?ServerRoot", line):
                value = line.split()
                apache_root = (value[1]).strip("\"\'")
    return apache_root


def apache_find_files(directory, regex, apache_root):
    '''
    Grabs all files from a directory that matches a regex passed
    from the function "apache_find_include", at the end of
    its execution will call out function "apache_find_include"
   '''
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            if fnmatch.fnmatch(name, regex):
                full_path = os.path.join(root, name)
                APACHE_INCLUDE_FILES.append(full_path)
                apache_find_include(full_path, apache_root)


def apache_find_include(conf, apache_root):
    '''
    Search every line of a given file and grabs the argument for
    Include/IncludeOptional directive, if the argument is a file
    will append to the "APACHE_INCLUDE_FILES" then call itsefl one
    more time if the file was not on the "APACHE_INCLUDE_FILES" list
    and if it finds a directory will call the function "apache_find_files"
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
                    if os.path.isfile(include):
                        if include not in APACHE_INCLUDE_FILES:
                            APACHE_INCLUDE_FILES.append(include)
                            apache_find_include(include, apache_root)
                    elif os.path.isdir(include):
                        regex = "*"
                        if include not in APACHE_INCLUDE_DIR:
                            apache_find_files(include, regex, apache_root)
                    elif not os.path.isdir(include):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = include.replace(regex, "")
                            if sanitized not in APACHE_INCLUDE_DIR:
                                apache_find_files(sanitized,
                                                  regex, apache_root)
                else:
                    full_path = apache_root.strip('\"') + "/" + include
                    if os.path.isfile(full_path):
                        if include not in APACHE_INCLUDE_FILES:
                            APACHE_INCLUDE_FILES.append(full_path)
                            apache_find_include(full_path, apache_root)
                    elif os.path.isdir(full_path):
                        regex = "*"
                        if full_path not in APACHE_INCLUDE_DIR:
                            apache_find_files(full_path,
                                              regex, apache_root)
                    elif not os.path.isdir(full_path):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = full_path.replace(regex, "")
                            if sanitized not in APACHE_INCLUDE_DIR:
                                apache_find_files(sanitized,
                                                  regex, apache_root)
    return APACHE_INCLUDE_FILES


def apache_fullpath_log(argument, apache_root):
    '''
    Function merely created for copy and paste ease,
    it will display the full path to the logs, rather then the relative one.
    '''
    full_log = ""
    if argument.startswith("$"):
        log_path = get_log_dir('APACHE_LOG_DIR')
        log_file = argument.split('/')[-1]
        full_log = log_path + "/" + log_file
    elif not argument.startswith("/"):
        full_log = apache_root + "/" + argument
    else:
        full_log = argument
    return full_log


def apache_domain_search(APACHE_INCLUDE_FILES, DOMAIN):
    '''
    Once the list "APACHE_INCLUDE_FILES" is populated
    this function goes over each file and looks for the domain in question
    '''
    vhosts = []
    for file in APACHE_INCLUDE_FILES:
        with open(file, "rt") as vhost:
            for line in vhost:
                no_white = line.strip()
                regex = "^\"?Server(Name|Alias)\"?.*" + DOMAIN + ".*"
                if re.search(regex, no_white):
                    vhosts.append(file)
                    break
    return vhosts


def sanitize_args(argument):
    '''
    Strips down all single and double quotes from lines
    '''
    sanitized = []
    for line in argument:
        clean = line.split(":")[0].strip('"\'')
        sanitized.append(clean)
    return sanitized


def apache_directive_finder(vhosts_file, apache_root):
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
                    except:
                        pass
                elif re.match("^(\"|')?CustomLog|^(\"|')?ErrorLog", no_white):
                    try:
                        vhost = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split(
                        )[1].strip('"\'').split(":")[0]
                        full_log = apache_fullpath_log(argument, apache_root)
                        vhost[directive] = full_log
                    except:
                        pass
                elif re.match("^(\"|')?Include|^(\"|')?SSLEngine", no_white):
                    try:
                        vhost = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split(
                        )[1].strip('"\'').split(":")[0]
                        vhost[directive] = argument
                    except:
                        pass
                elif re.match("^(\"|')?ServerAlias", no_white):
                    vhost = directives[i]
                    if "ServerAlias" not in vhost:
                        directive = no_white.split()[0].strip('"\'')
                        no_white_list = no_white.split()
                        no_white_list.pop(0)
                        argument = no_white_list
                        sanitized = sanitize_args(argument)
                        vhost[directive] = sanitized
                    else:
                        directive = no_white.split()[0].strip('"\'')
                        no_white_list = no_white.split()
                        no_white_list.pop(0)
                        argument = no_white_list
                        sanitized = sanitize_args(argument)
                        vhost["ServerAlias"] += sanitized
                elif re.match("</VirtualHost", no_white):
                    i += 1
    except (TypeError):
        pass
    return directives


def vhosts_files_parser(vhosts_files, apache_root):
    '''
    Goes over all the config files where the domain is
    mentioned and call the function to extract the main directives
    '''
    vhosts_directives = []
    if len(vhosts_files) == 0:
        print("No Apache vhosts found for the domain")
    for vhost_file in vhosts_files:
        vhosts_directives.extend(apache_directive_finder(vhost_file, apache_root))
    return vhosts_directives


def vhost_organizer(vhosts_directives, DOMAIN):
    '''
    Takes all the individual vhosts extract from previous function and
    removes all that does contain the "domain " in ServerName or ServerAlis
    '''
    vhosts = []
    for vhost_entry in vhosts_directives:
        for k, v in vhost_entry.items():
            if DOMAIN == v:
                vhosts.append(vhost_entry)
            elif 'ServerAlias' == k:
                for alias in v:
                    if DOMAIN == alias:
                        vhosts.append(vhost_entry)
    return vhosts


def apache_warn_include(vhosts):
    if 'Include' in vhosts:
        print("include in the vhost, some directives might be overwritten")
    return vhosts


def apache_default_log(vhosts):
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


def apache_output(vhosts):
    for entry in vhosts:
        for k in sorted(entry.keys()):
            if k == '.Vhost file':
                print("==============================")
                print(bcolors.YELLOW + '%15s' % "Vhost File"+':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == '<VirtualHost':
                print(bcolors.LIGHTRED + '%15s' % (str(k))+':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == 'ServerName':
                print(bcolors.LIGHTRED + '%15s' % (str(k))+':  '
                      + bcolors.ENDC + str(entry[k]))
                print("==============================")
            else:
                print(bcolors.LIGHTRED + '%15s' % (str(k))+':  '
                      + bcolors.ENDC + str(entry[k]))


def nginx_find_files(directory, regex):
    '''
    Grabs all files from a directory that matches a regex passed
    from the function "nginx_find_include", at the end of its
    execution will call out function "nginx_find_include"
   '''
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            if fnmatch.fnmatch(name, regex):
                full_path = os.path.join(root, name)
                NGINX_INCLUDE_FILES.append(full_path)
                nginx_find_include(full_path)


def nginx_find_include(conf):
    '''
    Search every line of a given file and grabs the argument for
    include/includeOptional directive, if the argument is a file
    will append to the "NGINX_INCLUDE_FILES" then call itsefl one
    more time if the file was not on the "NGINX_INCLUDE_FILES" list
    and if it finds a directory will call the function "nginx_find_files"
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
                        if include not in NGINX_INCLUDE_FILES:
                            NGINX_INCLUDE_FILES.append(include)
                            nginx_find_include(conf=include)
                    elif os.path.isdir(include):
                        regex = "*"
                        if include not in NGINX_INCLUDE_DIR:
                            nginx_find_files(directory=include, regex=regex)
                    elif not os.path.isdir(include):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = include.replace(regex, "")
                            if sanitized not in NGINX_INCLUDE_DIR:
                                nginx_find_files(
                                    directory=sanitized, regex=regex)
                else:
                    full_path = SERVER_ROOT.strip('\"') + "/" + include
                    if os.path.isfile(full_path):
                        if include not in NGINX_INCLUDE_FILES:
                            NGINX_INCLUDE_FILES.append(full_path)
                            nginx_find_include(conf=full_path)
                    elif os.path.isdir(full_path):
                        regex = "*"
                        if full_path not in NGINX_INCLUDE_DIR:
                            nginx_find_files(directory=full_path, regex=regex)
                    elif not os.path.isdir(full_path):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = full_path.replace(regex, "")
                            if sanitized not in NGINX_INCLUDE_DIR:
                                nginx_find_files(
                                    directory=sanitized, regex=regex)
    return NGINX_INCLUDE_FILES


def nginx_domain_search(NGINX_INCLUDE_FILES, DOMAIN):
    '''
    Once the list "NGINX_INCLUDE_FILES" is populated this function
    goes over each file and looks for the domain in question
    '''
    serverblocks = []
    for file in NGINX_INCLUDE_FILES:
        with open(file, "rt") as serverblock:
            for line in serverblock:
                no_white = line.strip()
                regex = "^\"?server_name\"?.*" + DOMAIN + ".*"
                if re.search(regex, no_white):
                    serverblocks.append(file)
                    break
    return serverblocks


def sanitize_args(argument):
    '''
    Strips down all single and double quotes from lines
    '''
    sanitized = []
    for line in argument:
        clean = line.split(":")[0].strip('"\';')
        sanitized.append(clean)
    return sanitized


def nginx_fullpath_include(argument):
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


def nginx_directive_finder(serverblocks_file):
    '''
    Goes  over the select file(s) and returns only the relevant directives
    '''
    i = 0
    directives = []
    serverblocks = {}
    close_brackets = False
    inside_block = False
    open_count = 0
    close_count = 0
    regex = "^(\"|')?"
    try:
        with open(serverblocks_file, "rt") as serverblock:
            for line in serverblock:
                no_white = line.strip()
                if not no_white.startswith('#'):
                    if inside_block:
                        if '{' in no_white:
                            open_count += 1
                    else:
                        pass
                    if inside_block:
                        if '}' in no_white:
                            close_count += 1
                            if open_count == close_count:
                                i += 1
                                inside_block = False
                    else:
                        pass

                if re.match(r"server($|\s*{)", no_white):
                    inside_block = True
                    d1 = {}
                    directive = ".config file"
                    argument = serverblocks_file
                    d1[directive] = argument
                    directives.append(d1)
                    if "{" in no_white:
                        open_count += 1
                elif re.match(r"^(\"|')?root", no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split()[1].strip('"\';')
                        serverblock[directive] = argument
                    except:
                        pass
                elif re.match(r"^(\"|')?access_log|^(\"|')?error_log", no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split()[1].strip('"\';')
                        if argument == "on" or argument == "off":
                            pass
                        else:
                            serverblock[directive] = argument
                    except:
                        pass
                elif re.match(r"^(\"|')?proxy_pass|^(\"|')?fastcgi_pass", no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split()[1].strip('"\';')
                        serverblock[directive] = argument
                    except:
                        pass
                elif re.match("^(\"|')?include", no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split()[1].strip('"\';')
                        full_path = nginx_fullpath_include(argument)
                        serverblock[directive] = full_path
                    except:
                        pass
                elif re.match("^(\"|')?server_name", no_white):
                    try:
                        serverblock = directives[i]
                        if "server_name" not in serverblock:
                            directive = no_white.split()[0].strip('"\'')
                            no_white_list = no_white.split(";")[0].split()
                            no_white_list.pop(0)
                            argument = no_white_list
                            sanitized = sanitize_args(argument)
                            serverblock[directive] = sanitized
                        elif "server_name" in serverblock:
                            no_white_list = no_white.split(";")[0].split()
                            no_white_list.pop(0)
                            argument = no_white_list
                            sanitized = sanitize_args(argument)
                            serverblock["server_name"].extend(sanitized)
                    except:
                        pass
                elif re.match("^(\"|')?listen", no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\';')
                        no_white_list = no_white.split(";")[0].split()
                        no_white_list.pop(0)
                        argument = no_white_list
                        sanitized = sanitize_args(argument)
                        if "listen" not in serverblock:
                            serverblock[directive] = sanitized
                        else:
                            for option in sanitized:
                                serverblock[directive].append(option)
                    except:
                        pass
    except (TypeError):
        pass
    return directives


def serverblocks_files_parser(serverblocks_files):
    '''
    Goes over all the .config files where the domain is mentioned
    and call the function to extract the main directives
    '''
    if len(serverblocks_files) == 0:
        print("No Nginx server blocks found for the domain")
    serverblocks_directives = []
    for serverblock_file in serverblocks_files:
        serverblocks_directives.extend(
            nginx_directive_finder(serverblock_file))
    return serverblocks_directives


def serverblock_organizer(serverblocks_directives, DOMAIN):
    '''
    Takes all the individual serverblocks extract from previous function and
    removes all that does contain the "domain " in ServerName or ServerAlis
    '''
    serverblocks = []
    for block_entry in serverblocks_directives:
        if DOMAIN in block_entry['server_name']:
            serverblocks.append(block_entry)
    return serverblocks


def nginx_output(serverblocks):
    for entry in serverblocks:
        for k in sorted(entry.keys()):
            if k == 'server block':
                print("==============================")
                print(bcolors.LIGHTRED + '%15s' % (str(k))+':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == 'server_name':
                print(bcolors.LIGHTRED + '%15s' % (str(k))+':  '
                      + bcolors.ENDC + str(entry[k]))
                print("==============================")
                print("==============================")
            elif k == '.config file':
                print("==============================")
                print(bcolors.GREEN + '%15s' % "Server Block"+':  '
                      + bcolors.ENDC + str(entry[k]))
            else:
                print(bcolors.LIGHTRED + '%15s' % (str(k))+':  '
                      + bcolors.ENDC + str(entry[k]))


def main():
    DOMAIN = get_domain()
    get_dns(DOMAIN)
    apache, IS_APACHE, nginx, IS_NGINX = os_finder()
    inodePidMap = get_inodePidMap()
    inodes = populateInodes()
    listeningPorts = get_listeningPorts(inodes, inodePidMap)
    portOutput = get_portOutput(listeningPorts)

    if IS_APACHE:
        apache_root = apache_root_finder(apache)
        APACHE_INCLUDE_FILES = apache_find_include(apache, apache_root)
        vhosts_files = apache_domain_search(APACHE_INCLUDE_FILES, DOMAIN)
        vhosts_directives = vhosts_files_parser(vhosts_files, apache_root)
        vhosts = vhost_organizer(vhosts_directives, DOMAIN)
        apache_warn_include(vhosts)
        apache_default_log(vhosts)
        apache_output(vhosts)
        
    if IS_NGINX:
        NGINX_INCLUDE_FILES = nginx_find_include(conf=nginx)
        serverblocks_files = nginx_domain_search(NGINX_INCLUDE_FILES, DOMAIN)
        serverblocks_directives = serverblocks_files_parser(serverblocks_files)
        serverblocks = serverblock_organizer(serverblocks_directives, DOMAIN)
        nginx_output(serverblocks)


if __name__ == "__main__":
    main()

