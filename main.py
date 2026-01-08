#!/usr/bin/env python3

import json
import os, sys, re
from itertools import islice
from pathlib import Path
# Maintainer @httpnotonly
# How does it work
# 1. Find any danger function in project directory, that you specify
# 2. Tries to find the user input directly in such functions
from pprint import pprint
import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "--directory",
    "-d",
    required=True,
    help="Path to directory to scan"
)
parser.add_argument(
    "--output",
    "-o",
    required=True,
    help="path to write a result json file"
)
args = parser.parse_args()
directory = args.directory
output_path = Path(args.output)
output_path.parent.mkdir(parents=True, exist_ok=True)

global_assignments_map = {}

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
    "mysql_query",
    "pg_execute",
    "pg_query",
    "unserialize"
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
    '$_FILES',
    'PHP_SELF'
]

java_user_input_list = [
    '.getParameter',
    '@RequestParam'
]

working_dir = directory
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
                        global_assignments_map[filename] = {user_input_var.group(2): pattern}
        except Exception as ex:
            # It was not a text file
            pass
    return list(set(modified_user_input_list))


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

def get_code_from_file(filename, linenumber):
    code = ""
    with open(filename, 'r') as file:
        code = line = file.readlines()[int(linenumber)]
    return code

def get_code_range_from_file(filename, linenumber, lines_before):
    start = max(0, int(linenumber) - int(lines_before) - 1)
    end = int(linenumber) - 1  # current line is not interesting, we have get_code_from_file for it

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        lines = list(islice(f, start, end))

    return "".join(lines)

def search_user_input(user_input_list, filename, linenumber):
    result = {}
    reached_input_list = reach_user_input(user_input_list, filename)
    code = get_code_from_file(filename, linenumber)
    for pattern in reached_input_list:
        if re.compile(r'\(.*' + re.escape(pattern) + r'.*\)').search(code):
            result[str('%s:%s' % (filename, linenumber))] = pattern
    return result


def find_interesting(dangerous_functions_list, user_input_list):
    result = []
    for file in get_files_in_working_dir():
        evil_functions_places = find_danger_functions(dangerous_functions_list, file)
        if evil_functions_places:
            # result example
            # {'./xss.php:310': 'eval', './xss.php:658': 'eval'}
            # [
            #  {
            #    "filepath": "./xss.php",
            #    "line_number": 310,
            #    "function": "eval",
            #    "channel": "GET",
            #  }
            # ]
            for function_place in evil_functions_places.keys():
                filename = function_place.split(':')[0]
                linenumber = function_place.split(':')[1]
                code = get_code_from_file(filename, linenumber)
                code_before_line = get_code_range_from_file(filename, linenumber, 20)
                evil_input_places = search_user_input(user_input_list, filename, linenumber)
                if evil_input_places:
                    finding = {}
                    finding["title"] = 'Found "%s" function and "%s" inside a function as a user input' % \
                                       (evil_functions_places.get(function_place),
                                        evil_input_places.get(function_place))
                    finding["filepath"] = filename.replace(directory + "/", '')
                    finding["line_number"] = int(linenumber) + 1
                    finding["function_name"] = evil_functions_places.get(function_place)
                    finding["variable"] = evil_input_places.get(function_place)
                    finding["channel"] = global_assignments_map.get(filename).get(evil_input_places.get(function_place))
                    finding["code_sample"] = code
                    finding["severity"] = "MEDIUM_RARE"
                    finding["code_before_function"] = code_before_line
                    result.append(finding)
    return result


if __name__ == "__main__":
    report = find_interesting(dangerous_functions_list, user_input_list)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    exit(0)