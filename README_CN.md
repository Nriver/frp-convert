# frp-convert
将 [frp](https://github.com/fatedier/frp) 配置文件从 ini 格式转换为 toml 格式。

[English README](README.md)

## 前提条件

- 需要 Python 3。

### 安装依赖

安装所需的 Python 依赖项，请运行以下命令：

```bash
pip install toml
````

## 使用方法

### 从 ini 转换为 toml

将 convert.py 放到 frp 配置同目录下。

要将 frp 配置文件从 ini 格式转换为 toml 格式，使用以下命令：

```bash
python convert.py frpc.ini frpc.toml
python convert.py frps.ini frps.toml
```

### 使用 toml 配置启动 frp

转换完成后，您可以使用 toml 配置文件启动 frp：

```bash
./frpc -c ./frpc.toml
./frps -c ./frps.toml
```