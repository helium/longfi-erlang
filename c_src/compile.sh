#!/bin/sh

VERSION="0.2.0"


if [ ! -d c_src/longfi-core ]; then
    git clone https://github.com/helium/longfi-core.git c_src/longfi-core
fi

cd c_src/longfi-core

CURRENT_VERSION=`git describe --tags`

if [ ! "$VERSION" = "$CURRENT_VERSION" ]; then
    git clean -ddxxff
    git fetch
    git checkout $VERSION
fi

if [ ! -d build ]; then
    cmake -H. -Bbuild -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
fi
make -C build -j
