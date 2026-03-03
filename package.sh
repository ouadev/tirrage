CURRENT_TAG=$(git describe --tags)

package_linux() {
    ./resources/linux/package-linux.sh $CURRENT_TAG
}

package_windows() {
    ./resources/windows/package-win.sh $CURRENT_TAG
}

package_linux
package_windows
