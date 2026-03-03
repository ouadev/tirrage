CURRENT_TAG=$(git describe --tags)

sudo apt remove tirrage
sudo dpkg -i packages/linux-release/tirrage_$CURRENT_TAG.deb