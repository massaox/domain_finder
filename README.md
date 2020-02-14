# domain_finder
Script created to assist troubleshooting issues with LAMP and LEMP stack. It only requires the domain to be investigate as input. Script will tell you:

1- Which interface Apache/Ngnix is listening to;

2- DNS record of the domain queried against Google's Name Server (8.8.8.8), falls back to NameServers from the server if Google fails;

3- Directives such as DocumentRoot/root, CustomLog/access_log, ErrorLog/error_log;

Simply run the script with no arguments, you will be prompt do type the domain you are looking for.
