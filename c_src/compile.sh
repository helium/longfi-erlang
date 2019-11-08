#!/bin/sh

VERSION="0.1.0"


if [ ! -d c_src/longfi-core ]; then
    git clone https://github.com/helium/longfi-core.git c_src/longfi-core
fi

cd c_src/longfi-core

CURRENT_VERSION=`git describe --tags`

#if [ ! "$VERSION" = "$CURRENT_VERSION" ]; then
    #git clean -ddxxff
    #git fetch
    #git checkout $VERSION
#fi

git fetch
git checkout jsk/api/add-fp-verification
git pull origin jsk/api/add-fp-verification

if [ ! -d build ]; then
    cmake -H. -Bbuild -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
fi
make -C build -j
