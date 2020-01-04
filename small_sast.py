import os, sys, re
# Maintainer @httpnotonly
# How does it work
# 1. Find any danger function in project directory, that you specify
# 2. Tries to find the user input directly in such functions
from pprint import pprint

php_danger_functions_list = [
    "exec",
    "eval",
    "system",
    "popen",
    "proc_open",
    "shell_exec",
    "pcntl_exec",
    "fopen",
    "move_uploaded_file",
    "file_get_contents",
    "mysql_query"
]

java_danger_functions_list = [
    "exec",
    "eval",
    "SAXBuilder",
    "renderFragment",
    "sendRedirect",
    "readAllBytes",
    "writeRawValue",
    "File",
    "ProcessBuilder",
    "createQuery",
    "loadLibrary",
    "equals"
]

dotnet_danger_functions_list = [
    "Deserialize",
]

php_user_input_list = [
    '$_GET',
    '$_POST',
    '$_REQUEST',
    '$_COOKIE',
    'PHP_SELF'
]

java_user_input_list = [
    '.getParameter',
    '@RequestParam'
]

working_dir = '.'
dangerous_functions_list = php_danger_functions_list
user_input_list = php_user_input_list


def reach_user_input(user_input_list, filename):
    """
    Finds expressions like:
    $var = $_GET
    :param user_input_list:
    :param filename:
    :return modified_user_input_list:
    """
    modified_user_input_list = user_input_list
    with open(filename, 'r') as file:
        try:
            for line in file.readlines():
                for pattern in user_input_list:
                    user_input_var = re.compile(r'(\w+\s)?(\$?\w+)\s?=\s?' + re.escape(pattern)).search(line)
                    if user_input_var:
                        modified_user_input_list.append(user_input_var.group(2))
        except Exception as ex:
            # It was not a text file
            pass
    return modified_user_input_list


def get_files_in_working_dir():
    result = []
    for (dirpath, dirnames, files) in os.walk(working_dir):
        for file in files:
            result.append(os.path.join(dirpath, file))
    return result


def find_danger_functions(function_list, filename):
    result = {}
    with open(filename, 'r') as file:
        try:
            for linenumber, line in enumerate(file):
                for pattern in function_list:
                    if re.compile(pattern + r'\(').search(line):
                        result[str('%s:%s' % (filename, linenumber))] = pattern
        except Exception as ex:
            # we got some non-text files
            pass
    return result


def search_user_input(user_input_list, filename, linenumber):
    result = {}
    reached_input_list = reach_user_input(user_input_list, filename)
    with open(filename, 'r') as file:
        line = file.readlines()[int(linenumber)]
    for pattern in reached_input_list:
        if re.compile(r'\(.*' + re.escape(pattern) + r'.*\)').search(line):
            result[str('%s:%s' % (filename, linenumber))] = pattern
    return result


def find_interesting(dangerous_functions_list, user_input_list):
    result = {}
    for file in get_files_in_working_dir():
        evil_functions_places = find_danger_functions(dangerous_functions_list, file)
        if evil_functions_places:
            # result example
            # {'./xss.php:310': 'eval', './xss.php:658': 'eval'}
            for function_place in evil_functions_places.keys():
                filename = function_place.split(':')[0]
                linenumber = function_place.split(':')[1]
                evil_input_places = search_user_input(user_input_list, filename, linenumber)
                if evil_input_places:
                    result[function_place] = 'Found "%s" function and "%s" inside a function as the user input' % \
                                             (evil_functions_places.get(function_place), evil_input_places.get(function_place))
    return result


if __name__ == "__main__":
    pprint(find_interesting(dangerous_functions_list, user_input_list))
