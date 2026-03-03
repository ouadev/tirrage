# Generate an EXE file for Windows from Linux.
#
# Instructions to cross-compile Tirrage for Windows.

VERSION="$1"

mkdir -p packages/


# Build the application.
cargo build --target x86_64-pc-windows-gnu --profile release --bin tirrage

# Copy the exe
cp target/x86_64-pc-windows-gnu/release/tirrage.exe packages/tirrage-$VERSION.exe
