# 从源码打包

打包分两步：先用 PyInstaller 把程序编译成一个文件夹，再用 Inno Setup 把它做成安装包。打包时不会联网，也不会自己安装任何依赖。

## 需要的工具

作者打包时用的是下面这些版本：

| 工具 | 版本 | 来源 |
|---|---|---|
| Python（带 Tkinter） | 3.12.10 x64 | [python.org](https://www.python.org/downloads/release/python-31210/) |
| PyInstaller | 6.22.3 | [PyPI](https://pypi.org/project/pyinstaller/6.22.3/) |
| Inno Setup | 6.7.4 | [jrsoftware.org](https://jrsoftware.org/isdl.php) |

`build.py` 只认装在 `packaging/tooling/` 下面的 PyInstaller，不会用系统里装的那份。所以请把 PyInstaller 和它的依赖装到 `packaging/tooling/` 里的某个文件夹，然后把这个文件夹加进 `PYTHONPATH`。另外，`ISCC.exe` 要么能在 `PATH` 里找到，要么装在 `Inno Setup 6` 默认目录下。

## 命令

```bash
python -B packaging/build.py --check
python -B packaging/build.py --build --version 1.0.0 --output <一个尚不存在的绝对路径>
```

- `--check` 会报告各项工具是否齐全，显示 `status: ready` 才能打包。
- 输出目录必须是绝对路径，而且这个目录本身不能已经存在，它的上一级目录必须存在。打包失败时，这个目录会保留下来，方便检查。
- 打包完成后，安装包在 `<输出目录>/installer/` 里面。

## 打包时自动检查的内容

- 只打包 `build.py` 里列出的源码文件，并记录每个文件的 SHA-256。
- 发现源码里写死了本机端口、Windows 用户目录、带用户名的网址或固定公网 IP，就直接报错停止。
- 安装包里不能有配置文件、数据库、密钥这类文件。
- 打包出的程序会运行一遍 `--self-check` 自检。这次自检不读用户配置，也不联网。

这些检查只能减少误打包，不能证明二进制文件里一定没有敏感内容。发布前请自己再检查一遍。

## 第三方许可证

安装包里附带的第三方组件许可证放在 `licenses/`，包括：

- Python
- Tcl/Tk
- OpenSSL
- zlib
- XZ
- libmpdec
- PyInstaller
- Inno Setup

安装包里还带有 Python 官方发行版自带的 Microsoft Visual C++ 运行库（`VCRUNTIME140*.dll`），它的再分发条件请以 Microsoft 的[说明](https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files)为准。
