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


def std_exceptions(etype, value, tb):
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


sys.excepthook = std_exceptions


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


def get_inode_pid_map():
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


def populate_inodes():
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


def get_listeningPorts(inodes, inodePidMap):
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


def get_domain():
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


def output_dns(domain):
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
                print (domain + " points to " + bcolors.CYAN + dns + bcolors.ENDC)
            except (KeyError):
                print("There is no A record for this domain")
        else:
            print("There is no A record for this domain")
    except (socket.timeout):
        get_dns_locally(domain)


def output_dns_locally(domain):
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


def get_os(op_sys=str(platform.linux_distribution())):
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


def get_apacheRoot(apache):
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


def apache_find_files(directory, regex, apacheRoot, apacheIncludeFiles,
                      apacheIncludeDir):
    '''
    Grabs all files from a directory that matches a regex passed
    from the function "get_apache_include", at the end of
    its execution will call out function "get_apache_include"
   '''
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            if fnmatch.fnmatch(name, regex):
                full_path = os.path.join(root, name)
                apacheIncludeFiles.append(full_path)
                get_apache_include(full_path, apacheRoot, apacheIncludeFiles,
                                   apacheIncludeDir)


def get_apache_include(conf, apacheRoot, apacheIncludeFiles,
                       apacheIncludeDir):
    '''
    Search every line of a given file and grabs the argument for
    Include/IncludeOptional directive, if the argument is a file
    will append to the "apacheIncludeFiles" then call itself one
    more time if the file was not on the "apacheIncludeFiles" list
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
                    if os.path.isfile(
                            include) and include not in apacheIncludeFiles:
                        apacheIncludeFiles.append(include)
                        get_apache_include(include, apacheRoot,
                                           apacheIncludeFiles,
                                           apacheIncludeDir)
                    elif os.path.isdir(include):
                        apacheIncludeDir.append(include)
                        regex = "*"
                        if include not in apacheIncludeDir:
                            apache_find_files(include, regex, apacheRoot,
                                              apacheIncludeFiles,
                                              apacheIncludeDir)
                    elif not os.path.isdir(include):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = include.replace(regex, "")
                            if sanitized not in apacheIncludeDir:
                                apache_find_files(sanitized,
                                                  regex, apacheRoot,
                                                  apacheIncludeFiles,
                                                  apacheIncludeDir)
                else:
                    full_path = apacheRoot.strip('\"') + "/" + include
                    if os.path.isfile(
                            full_path) and include not in apacheIncludeFiles:
                        apacheIncludeFiles.append(full_path)
                        get_apache_include(full_path, apacheRoot,
                                           apacheIncludeFiles,
                                           apacheIncludeDir)
                    elif os.path.isdir(full_path):
                        regex = "*"
                        if full_path not in apacheIncludeDir:
                            apache_find_files(full_path,
                                              regex, apacheRoot,
                                              apacheIncludeFiles,
                                              apacheIncludeDir)
                    elif not os.path.isdir(full_path):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = full_path.replace(regex, "")
                            if sanitized not in apacheIncludeDir:
                                apache_find_files(sanitized, regex,
                                                  apacheRoot, apacheIncludeFiles,
                                                  apacheIncludeDir)
    return apacheIncludeFiles


def apache_fullpath_log(argument, apacheRoot):
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
        full_log = apacheRoot + "/" + argument
    else:
        full_log = argument
    return full_log


def apache_domain_search(apacheIncludeFiles, domain):
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


def sanitize_args(argument):
    '''
    Strips down all single and double quotes from lines
    '''
    sanitized = []
    for line in argument:
        clean = line.split(":")[0].strip('"\'')
        sanitized.append(clean)
    return sanitized


def apache_directive_finder(vhosts_file, apacheRoot):
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
                        full_log = apache_fullpath_log(argument, apacheRoot)
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


def vhosts_files_parser(vhostsFiles, apacheRoot):
    '''
    Goes over all the config files where the domain is
    mentioned and call the function to extract the main directives
    '''
    vhostsDirectives = []
    if len(vhostsFiles) == 0:
        print("No " + bcolors.YELLOW + "Apache" + bcolors.ENDC
              + " vhosts found for the domain")
        print("")
    for vhost_file in vhostsFiles:
        vhostsDirectives.extend(apache_directive_finder
                                (vhost_file, apacheRoot))
    return vhostsDirectives


def vhost_organizer(vhostsDirectives, domain):
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


def nginx_find_files(directory, regex, nginxIncludeFiles, nginxIncludeDir):
    '''
    Grabs all files from a directory that matches a regex passed
    from the function "get_nginx_include", at the end of its
    execution will call out function "get_nginx_include"
   '''
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            if fnmatch.fnmatch(name, regex):
                full_path = os.path.join(root, name)
                nginxIncludeFiles.append(full_path)
                get_nginx_include(full_path, nginxIncludeFiles,
                                  nginxIncludeDir)


def get_nginx_include(conf, nginxIncludeFiles, nginxIncludeDir):
    '''
    Search every line of a given file and grabs the argument for
    include/includeOptional directive, if the argument is a file
    will append to the "nginxIncludeFiles" then call itsefl one
    more time if the file was not on the "nginxIncludeFiles" list
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
                        if include not in nginxIncludeFiles:
                            nginxIncludeFiles.append(include)
                            get_nginx_include(include, nginxIncludeFiles,
                                              nginxIncludeDir)
                    elif os.path.isdir(include):
                        regex = "*"
                        if include not in nginxIncludeDir:
                            nginx_find_files(include, regex, nginxIncludeFiles,
                                             nginxIncludeDir)
                    elif not os.path.isdir(include):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = include.replace(regex, "")
                            if sanitized not in nginxIncludeDir:
                                nginx_find_files(
                                    sanitized, regex, nginxIncludeFiles,
                                    nginxIncludeDir)
                else:
                    full_path = "/etc/nginx/" + include
                    if os.path.isfile(full_path):
                        if include not in nginxIncludeFiles:
                            nginxIncludeFiles.append(full_path)
                            get_nginx_include(full_path, nginxIncludeFiles,
                                              nginxIncludeDir)
                    elif os.path.isdir(full_path):
                        regex = "*"
                        if full_path not in nginxIncludeDir:
                            nginx_find_files(
                                full_path, regex, nginxIncludeFiles,
                                nginxIncludeDir)
                    elif not os.path.isdir(full_path):
                        if fnmatch.fnmatch(include, "*[*]*"):
                            match = include.partition("*")
                            regex = "*" + match[2]
                            sanitized = full_path.replace(regex, "")
                            if sanitized not in nginxIncludeDir:
                                nginx_find_files(
                                    sanitized, regex, nginxIncludeFiles,
                                    nginxIncludeDir)
    return nginxIncludeFiles


def nginx_domain_search(nginxIncludeFiles, domain):
    '''
    Once the list "nginxIncludeFiles" is populated this function
    goes over each file and looks for the domain in question
    '''
    blocks = []
    for file in nginxIncludeFiles:
        with open(file, "rt") as serverblock:
            for line in serverblock:
                no_white = line.strip()
                regex = "^\"?server_name\"?.*" + domain + ".*"
                if re.search(regex, no_white):
                    blocks.append(file)
                    break
    return blocks


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
    blocks = {}
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
                    except BaseException:
                        pass
                elif re.match(r"^(\"|')?access_log|^(\"|')?error_log",
                              no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split()[1].strip('"\';')
                        if argument == "on" or argument == "off":
                            pass
                        else:
                            serverblock[directive] = argument
                    except BaseException:
                        pass
                elif re.match(r"^(\"|')?proxy_pass|^(\"|')?fastcgi_pass",
                              no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split()[1].strip('"\';')
                        serverblock[directive] = argument
                    except BaseException:
                        pass
                elif re.match("^(\"|')?include", no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[0].strip('"\'')
                        argument = no_white.split()[1].strip('"\';')
                        full_path = nginx_fullpath_include(argument)
                        serverblock[directive] = full_path
                        print( bcolors.CYAN + "Include  " + bcolors.ENDC + "detected on the block, please look at the file for futher configurations")
                    except BaseException:
                        pass
                elif re.match("^(\"|')?set", no_white):
                    try:
                        serverblock = directives[i]
                        directive = no_white.split()[1].strip('"\'')
                        argument = no_white.split()[2].strip('"\';')
                        variable = "variable " + directive
                        serverblock[variable] = argument
                    except BaseException:
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
                    except BaseException:
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
                    except BaseException:
                        pass
    except (TypeError):
        pass
    return directives


def serverblocks_files_parser(blocksFile):
    '''
    Goes over all the .config files where the domain is mentioned
    and call the function to extract the main directives
    '''
    if len(blocksFile) == 0:
        print("No " + bcolors.GREEN + "Nginx" + bcolors.ENDC
              + " server blocks were found for the domain")
        print("")
    blocksDirectives = []
    for serverblock_file in blocksFile:
        blocksDirectives.extend(
            nginx_directive_finder(serverblock_file))
    return blocksDirectives


def serverblock_organizer(blocksDirectives, domain):
    '''
    Takes all the individual serverblocks extract from previous function and
    removes all that does contain the "domain " in ServerName or ServerAlis
    '''
    blocks = []
    for block_entry in blocksDirectives:
        if domain in block_entry['server_name']:
            blocks.append(block_entry)
    return blocks


def output_port_ip(listeningPorts):
    apache = "(httpd|apache)"
    nginx = "(nginx)"
    for k in listeningPorts:
        if re.search(apache, str(k)):
            print("==============================")
            print(bcolors.YELLOW + "Apache " + bcolors.ENDC +
                  "is listening on %s" % listeningPorts[k])
            print("")
        elif re.search(nginx, str(k)):
            print("==============================")
            print(bcolors.GREEN + "Nginx " + bcolors.ENDC +
                  "is listening on %s" % listeningPorts[k])
            print("")


def output_apache(vhosts):
    print("==============================")
    for entry in vhosts:
        for k in sorted(entry.keys()):
            if k == '.Vhost file':
                print("==============================")
                print(bcolors.YELLOW + '%15s' % "Vhost File" + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == '<VirtualHost':
                print(bcolors.LIGHTRED + '%15s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == 'ServerName':
                print(bcolors.LIGHTRED + '%15s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
                print("==============================")
            else:
                print(bcolors.LIGHTRED + '%15s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
    print("==============================")


def output_nginx(blocks):
    print("==============================")
    print("==============================")
    for entry in blocks:
        for k in sorted(entry.keys()):
            if k == 'server block':
                print(bcolors.LIGHTRED + '%20s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == 'server_name':
                print(bcolors.LIGHTRED + '%20s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == '.config file':
                print(bcolors.GREEN + '%20s' % "Server Block" + ':  '
                      + bcolors.ENDC + str(entry[k]))
            elif k == 'include':
                print(bcolors.CYAN + '%20s' % "include" + ':  '
                      + bcolors.ENDC + str(entry[k]))
            else:
                print(bcolors.LIGHTRED + '%20s' % (str(k)) + ':  '
                      + bcolors.ENDC + str(entry[k]))
    print("==============================")
    print("==============================")


def main():
    apacheIncludeDir = []
    isApache = False
    isNginx = False
    nginxIncludeDir = []

    domain = get_domain()
    output_dns(domain)
    apache, isApache, apacheIncludeFiles, nginx, isNginx, nginxIncludeFiles = get_os()
    inodePidMap = get_inode_pid_map()
    inodes = populate_inodes()
    listeningPorts = get_listeningPorts(inodes, inodePidMap)
    portOutput = output_port_ip(listeningPorts)

    if isApache:
        apacheRoot = get_apacheRoot(apache)
        apacheIncludeFiles = get_apache_include(apache, apacheRoot,
                                                apacheIncludeFiles,
                                                apacheIncludeDir)
        vhostsFiles = apache_domain_search(apacheIncludeFiles, domain)
        vhostsDirectives = vhosts_files_parser(vhostsFiles, apacheRoot)
        vhosts = vhost_organizer(vhostsDirectives, domain)
        apache_warn_include(vhosts)
        apache_default_log(vhosts)
        output_apache(vhosts)
    if isNginx:
        nginxIncludeFiles = get_nginx_include(nginx, nginxIncludeFiles,
                                              nginxIncludeDir)
        blocksFile = nginx_domain_search(nginxIncludeFiles, domain)
        blocksDirectives = serverblocks_files_parser(blocksFile)
        blocks = serverblock_organizer(blocksDirectives, domain)
        output_nginx(blocks)


if __name__ == "__main__":
    main()

