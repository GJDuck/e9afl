#!/bin/bash
#
# Copyright (C) 2022 National University of Singapore
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

VERSION=855e8b8092f27ec5c3deb1bc1e7b28e50da6800f

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
    echo -e "${GREEN}$0${OFF}: e9patch has been built..."
else
	echo -e "${GREEN}$0${OFF}: using existing e9patch..."
fi

# STEP (2): build the E9Tool plugin:
echo -e "${GREEN}$0${OFF}: building the e9afl plugin..."
echo "g++ -std=c++11 -fPIC -shared -o e9AFLPlugin.so -O2 e9AFLPlugin.cpp -I ."
g++ -std=c++11 -fPIC -shared -o e9AFLPlugin.so -O2 e9AFLPlugin.cpp \
    -I e9patch-$VERSION/src/e9tool/
strip e9AFLPlugin.so
chmod a-x e9AFLPlugin.so

# STEP (3): build the runtime:
echo -e "${GREEN}$0${OFF}: building the e9afl runtime..."
e9patch-$VERSION/e9compile.sh afl-rt.c -I e9patch-$VERSION/examples/ \
    -I e9patch-$VERSION/src/e9patch/ -DNO_GLIBC=1
chmod a-x afl-rt

# STEP (4): build the driver:
g++ -std=c++11 -fPIC -pie -O2 -o e9afl e9afl.cpp
strip e9afl

# STEP (5): build the installation package:
rm -rf install
mkdir -p install
cp e9patch-$VERSION/e9patch install
cp e9patch-$VERSION/e9tool install
mv e9AFLPlugin.so install
mv afl-rt install
mv e9afl install
ln -s install/e9afl
ln -s install/afl-rt

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
echo "    afl-fuzz -m none -i input/ -o output/ -- ./readelf.afl -a @@"
echo

