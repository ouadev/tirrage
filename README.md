<div align="center">



# tirrage

[![License](https://img.shields.io/crates/l/iced.svg)](https://github.com/iced-rs/iced/blob/master/LICENSE)

file encryption using  [Age v1](https://github.com/FiloSottile/age) with a passphrase (Scrypt)


</div>


## Description
A Rust implementation of the Age v1 file encryption format, supporting only scrypt-based passphrase encryption. Other recipient types are not supported.


## Platforms

Primarily developed and tested on Linux. Windows and macOS support "should" also work.


## Command Line 

``` 
tirrage Command Line.

Usage:

$ tirra COMMAND [ARGUMENTS]

tirra  ver
tirra  decrypt	IN_FILE OUT_FILE
tirra  encrypt	IN_FILE OUT_FILE 


COMMANDS
       ver    Display the version information and exit.
       decrypt
              Decrypt a file that was encrypted using Age v1/scrypt recipient type.
       encrypt
              Encrypt a plaintext file using Age v1/scrypt recipient type

ARGUMENTS
       IN_FILE & OUT_FILE
              input and output file paths

```