# frp-convert
Convert  [frp](https://github.com/fatedier/frp) configuration files from ini format to toml format.

[中文说明](README_CN.md)

## Prerequisites

- Python 3 is required.

### Install dependencies

To install the required Python dependencies, run the following command:

```bash
pip install toml
````

## Usage

### Convert ini to toml

Put convert.py to the same folder with the frp config files.

To convert your frp configuration files from ini to toml, use the following commands:

```bash
python convert.py frpc.ini frpc.toml
python convert.py frps.ini frps.toml
```

### Start frp with toml configuration

Once converted, you can start frp using the toml configuration files:

```bash
./frpc -c ./frpc.toml
./frps -c ./frps.toml
```