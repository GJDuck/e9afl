#!/bin/bash
#
# Copyright (C) 2020 National University of Singapore
#
# This program is free software: you can redistribute it and/or modify
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

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

set -e

VERSION=eb5f00a344f6da77fab843b983e337d153496d3d

# STEP (1): install e9patch if necessary:
if [ ! -x e9patch-$VERSION/e9patch ]
then
    if [ ! -f e9patch-$VERSION.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading e9patch-$VERSION.zip..."
        wget -O e9patch-$VERSION.zip https://github.com/GJDuck/e9patch/archive/$VERSION.zip
    fi

    echo -e "${GREEN}$0${OFF}: extracting e9patch-$VERSION.zip..."
    unzip e9patch-$VERSION.zip

    echo -e "${GREEN}$0${OFF}: building e9patch..."
    cd e9patch-$VERSION
    ./build.sh
    cd ..
    ln -f -s e9patch-$VERSION/e9patch
    ln -f -s e9patch-$VERSION/e9tool
    ln -f -s e9patch-$VERSION/e9compile.sh
    ln -f -s e9patch-$VERSION/capstone
    ln -f -s e9patch-$VERSION/examples/stdlib.c
    echo -e "${GREEN}$0${OFF}: e9patch has been built..."
else
	echo -e "${GREEN}$0${OFF}: using existing e9patch..."
fi

# STEP (2): build the E9Tool plugin:
echo -e "${GREEN}$0${OFF}: building the e9afl plugin..."
echo "g++ -std=c++11 -fPIC -shared -o e9afl.so -O2 e9afl.cpp -I . -I capstone/include/"
g++ -std=c++11 -fPIC -shared -o e9afl.so -O2 e9afl.cpp \
    -I e9patch-$VERSION/src/e9tool/ -I capstone/include/

# STEP (3): build the runtime:
echo -e "${GREEN}$0${OFF}: building the e9afl runtime..."
./e9compile.sh afl-rt.c

echo -e "${GREEN}$0${OFF}: done!"
echo

echo -e "${YELLOW}       ___    _    _____ _"    
echo -e "  ___ / _ \\  / \\  |  ___| |"
echo -e " / _ \\ (_) |/ _ \\ | |_  | |"
echo -e "|  __/\\__, / ___ \\|  _| | |___"
echo -e " \\___|  /_/_/   \\_\\_|   |_____|${OFF}"
echo
echo "USAGE:"
echo
echo "    To use, simply run the command:"
echo
echo "        ./e9afl /path/to/binary"
echo
echo "    This will generate an AFL-instrumented \"binary.afl\" which can be"
echo "    used with afl-fuzz.  See the example below."
echo
echo "    Note that E9Patch uses a lot of virtual address space, so typically"
echo "    afl-fuzz should be run with a suitably high memory limit.  See the"
echo "    \`-m' option for afl-fuzz."
echo
echo "EXAMPLE:"
echo
echo "    ./e9afl readelf"
echo "    mkdir -p input"
echo "    mkdir -p output"
echo "    head -n 1 \`which ls\` > input/exe"
echo "    afl-fuzz -m 500000000 -i input/ -o output/ -- ./readelf.afl -a @@"
echo

