#!/usr/bin/env python3

import os
import re

SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))

libs = [
    'libequibit_cli',
    'libequibit_common',
    'libequibit_crypto',
    'libequibit_server',
    'libequibit_util',
    'libequibit_wallet',
    'libequibit_zmq',
]

ignore_list = [
    'rpc/net.cpp',
    'interfaces/handler.cpp',
    'interfaces/node.cpp',
    'interfaces/wallet.cpp',
]

lib_sources = {}


def parse_makefile(makefile):
    with open(makefile, 'r', encoding='utf-8') as file:
        current_lib = ''
        for line in file.read().splitlines():
            if current_lib:
                source = line.split()[0]
                if source.endswith('.cpp') and not source.startswith('$') and source not in ignore_list:
                    lib_sources[current_lib].append(source.replace('/', '\\'))
                if not line.endswith('\\'):
                    current_lib = ''
                continue
            for lib in libs:
                _lib = lib.replace('-', '_')
                if re.search(_lib + '.*_SOURCES \\= \\\\', line):
                    current_lib = lib
                    lib_sources[current_lib] = []
                    break


def main():
    print ("\n Warning: Ensure Makefiles and VS folders have the same file format. (ex. Bitcoin or Equibit) \n")
    for makefile_name in os.listdir(SOURCE_DIR):
        if 'Makefile' in makefile_name:
            parse_makefile(os.path.join(SOURCE_DIR, makefile_name))
    print ("item {} \n".format(lib_sources.items()))
    print ("\n")
    for key, value in lib_sources.items():
        vcxproj_filename = os.path.abspath(os.path.join(os.path.dirname(__file__), key, key + '.vcxproj'))
        print ("vcxproj_filename {} \n".format(vcxproj_filename))
        content = ''
        for source_filename in value:
            content += '    <ClCompile Include="..\\..\\src\\' + source_filename + '" />\n'
        with open(vcxproj_filename + '.in', 'r', encoding='utf-8') as vcxproj_in_file:
            with open(vcxproj_filename, 'w', encoding='utf-8') as vcxproj_file:
                vcxproj_file.write(vcxproj_in_file.read().replace(
                    '@SOURCE_FILES@\n', content))


if __name__ == '__main__':
    main()
