# file_cipher

```shell
Simply use xor to encrypt and decrypt files

Usage: file_cipher [OPTIONS] --input <INPUT> --output <OUTPUT> --xor <XOR>

Options:
  -i, --input <INPUT>    input file path or input directory
  -o, --output <OUTPUT>  output directory
  -e, --encrypt          encrypt the input file
  -d, --decrypt          decrypt the input file
  -x, --xor <XOR>        each byte of the input file is xor evaluated against this value, and it can't be zero
  -h, --help             Print help
  -V, --version          Print version
```

# Install

### Build Install
```bash
git clone https://github.com/0x1306a94/file_cipher
cd file_cipher
cargo install --path .
```

### macOS
  - #### Manual installation
    * [Download Release file_cipher-macos-universal-binaries.zip](https://github.com/0x1306a94/file_cipher/releases)
    ```sh
    unzip file_cipher-macos-universal-binaries.zip
    cp file_cipher /usr/local/bin/file_cipher
    sudo chmod +x /usr/local/bin/file_cipher
    ```
  - #### Homebrew installation
  ```sh
  brew tap 0x1306a94/homebrew-tap
  brew install file_cipher
  ```

### Windows
[Download Release](https://github.com/0x1306a94/file_cipher/releases)