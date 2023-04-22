# file_cipher

```shell
Simply use xor to encrypt and decrypt files

Usage: file_cipher [OPTIONS] --input <INPUT> --output <OUTPUT> --xor <XOR>

Options:
  -i, --input <INPUT>    input file path
  -o, --output <OUTPUT>  output file, if it is a directory, the final output file path is OUTPUT/INPUT.filename
  -e, --encrypt          encrypt the input file
  -d, --decrypt          decrypt the input file
  -x, --xor <XOR>        each byte of the input file is xor evaluated against this value, and it can't be zero
  -h, --help             Print help
  -V, --version          Print version
```
