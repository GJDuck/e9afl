#!/bin/bash
#
# Copyright (C) 2021 National University of Singapore
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

NAME=e9afl
VERSION=0.3.0

if [ ! -x install/e9afl ]
then
    echo -e "${RED}$0${OFF}: run ./build.sh first" 1>&2
    exit 1
fi

set -e

cd install/
mkdir -p data
mkdir -p control

cd data/
mkdir -p "./usr/share/e9afl/"
cp "../afl-rt"         "./usr/share/e9afl/"
cp "../e9afl"          "./usr/share/e9afl/"
cp "../e9AFLPlugin.so" "./usr/share/e9afl/"
cp "../e9patch"        "./usr/share/e9afl/"
cp "../e9tool"         "./usr/share/e9afl/"
mkdir -p "./usr/bin/"
ln -s "../share/e9afl/e9afl" "./usr/bin/e9afl"
mkdir -p "./usr/share/man/man1/"
gzip --stdout ../../doc/e9afl.1 > ./usr/share/man/man1/e9afl.1.gz
tar cz --owner root --group root -f ../data.tar.gz .
md5sum `find ../data/ -type f -printf "%P "` > ../control/md5sums

cd ../control/
cat << EOF > control
Package: ${NAME}
Version: ${VERSION}
Maintainer: Gregory J. Duck <gregory@comp.nus.edu.sg>
Section: universe/devel
Priority: optional
Homepage: https://github.com/GJDuck/e9afl
Architecture: amd64
Depends: libc6 (>= 2.14)
Recommends: afl
Description: AFL binary instrumentation
 E9AFL is a tool for automatically adding American Fuzzy Lop (AFL)
 instrumentation to existing binary code using static binary rewriting.  This
 makes it possible to add AFL instrumentation to programs without
 recompilation, and is useful for cases where the source code is not available
 (i.e. commercial software).
 .
 E9AFL is designed to be scalable: it is based on the E9Patch static binary
 rewriting tool that can scale to very large software.  E9AFL implements
 several optimizations so that fuzzing speed is comparable to source-level
 instrumentation with afl-gcc.
EOF
tar cz --owner root --group root -f ../control.tar.gz control md5sums
cd ..
echo "2.0" > debian-binary
PACKAGE="${NAME}_${VERSION}_amd64.deb"
fakeroot ar cr "../${PACKAGE}" debian-binary control.tar.gz \
    data.tar.gz
rm -rf debian-binary control.tar.gz data.tar.gz data/ control/

echo -e "${GREEN}$0${OFF}: Successfully built ${YELLOW}${PACKAGE}${OFF}..."

DIR="${NAME}-${VERSION}"
TAR_GZ="${DIR}.tar.gz"
mkdir -p "${DIR}"
cp "afl-rt"         "${DIR}/"
cp "e9afl"          "${DIR}/"
cp "e9AFLPlugin.so" "${DIR}/"
cp "e9patch"        "${DIR}/"
cp "e9tool"         "${DIR}/"
tar cz --owner root --group root -f "../${TAR_GZ}" "$DIR"

echo -e "${GREEN}$0${OFF}: Successfully built ${YELLOW}${TAR_GZ}${OFF}..."

