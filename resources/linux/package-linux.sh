#!/bin/bash

TARGET="tirrage"
VERSION="$1"
PACKAGE_NAME="${TARGET}_${VERSION}"
ASSETS_DIR="resources/linux"
BINARY="target/release/tirrage"
PACKAGING_DIR="packages/linux-release/"
PACKAGE_PATH="$PACKAGING_DIR/$PACKAGE_NAME"

build() {
  cargo build --bin tirrage --profile release
}

package() {
  build

  rm -rf $PACKAGE_PATH

  install -Dm755 $BINARY -t $PACKAGE_PATH/usr/bin
  install -Dm644 $ASSETS_DIR/control -t $PACKAGE_PATH/DEBIAN/

  cd $PACKAGING_DIR
  dpkg-deb --build $PACKAGE_NAME
  echo "Packaged Deb Created ..."
}

# call main function

package
