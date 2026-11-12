# 代理检测助手（for Claude，非官方）

这是一个 Windows 小工具，适合用 Bright Data ISP 代理 + Proxy Manager 访问 Claude 的人：

- 用之前，先检查代理出口是否稳定、是否和你预期的一致；
- 检查通过后，从助手里启动 Claude 桌面端或专用 Chrome；
- 网页端还能持续监测，出口一有异常就自动断网。

> **非官方项目**：本项目与 Anthropic、Bright Data 都没有关系，也没有得到它们认可。Claude 是 Anthropic 的商标，Bright Data 是 Bright Data Ltd. 的商标。
> 使用前，请自己确认符合 Anthropic 的[服务地区与使用政策](https://www.anthropic.com/supported-countries)和 Bright Data 的使用条款。违规使用导致封号等后果，由使用者自己承担。

## 能做什么

| 功能 | 说明 |
|---|---|
| 一键查找并填入 | 自动找到 Proxy Manager 的程序、管理端口、代理端口和 1.679.135 安装包并完成核验；首次配置只需手动填预期 IP 和区域名 |
| 环境体检 | 逐项检查 Clash、Proxy Manager 版本和端口、代理类型、系统代理、三处出口是否一致、电脑时间、时区和语言，并给出改法 |
| 一键修复 | Proxy Manager 没运行或端口不工作时，确认 Claude 已关闭后只重启这一个 Proxy Manager；不会强制关闭 Claude |
| 启动前检测 | 出口 IP 是否等于你填的预期 IP；Proxy Manager 程序和端口是否对得上；经代理能否访问 Claude 检测地址 |
| 启动桌面端 | 检测通过后，带上代理参数启动 Claude 桌面端 |
| 打开网页端 | 检测通过后，打开你指定的专用 Chrome |
| 持续监测（网页端） | 定时核对专用 Chrome 的出口；发现异常就立刻断开它的网络，手动复检通过后再恢复 |
| 报告 | 检测、启动和监测结果可以复制或导出，默认隐藏完整 IP |

## 不能做什么

- 不安装、不修改 Proxy Manager、Chrome 和 Claude，也不改系统代理、时区和语言设置。唯一会动的是你确认过的“一键修复”：重启 Proxy Manager。
- 桌面端只在启动前检测，运行过程中不提供断网保护。
- 不保存账号和密码。配置以明文保存在本机 `%LOCALAPPDATA%\ClaudeLaunchCenter\settings.json`，所以任何输入框都不要填凭据。
- 管理器核验目前只支持 Proxy Manager **1.679.135** 版的安装包。

## 准备工作（按顺序看教程）

1. [购买并创建 Bright Data ISP 代理](docs/教程1-创建ISP代理.md)
2. [安装 Proxy Manager 并建好代理端口](docs/教程2-安装ProxyManager.md)
3. [助手首次配置与日常使用](docs/教程3-助手配置与使用.md)

## 安装

- **用安装包**：到本仓库的 Releases 页面下载 `ClaudeLaunchCenterSetup-x.y.z.exe`，双击安装。只装给当前用户，不需要管理员权限。安装包没有代码签名，Windows 可能会提示“未知发布者”。
- **自己从源码打包**：见 [packaging/README.md](packaging/README.md)。

系统要求：Windows 10/11 64 位。网页端持续监测要添加 Windows 筛选平台（WFP）规则；权限不够时，监测会停下并在报告里说明原因。

## 开发

需要 Python 3.10 或更高版本，并且带 Tkinter。不依赖任何第三方 Python 包。在仓库根目录先设置 `PYTHONPATH=.`，再运行：

```bash
python -B -m unittest discover -s tests/core
python -B -m unittest discover -s tests/ui
python -B -m unittest discover -s tests/browser
python -B -m unittest discover -s tests/protection
python -B -m unittest discover -s tests/packaging
```

| 目录 | 内容 |
|---|---|
| `src/ui` | Tk 界面 |
| `src/core` | 检测、监测、Proxy Manager 版本核验 |
| `src/browser` | 专用 Chrome 识别与出口核对 |
| `src/protection` | 本机转发与 WFP 断网规则 |
| `packaging` | 打包脚本与第三方许可证 |

## 已知局限

- 主要在作者自己的一台电脑上实测过。1.1.0 新增的端口兜底确认，同样的代码在作者另一台电脑（Windows 预览版，端口列表会漏掉 Proxy Manager 的端口）上体检通过；一键修复还没在真实故障上实测。
- 网页端持续监测的长时间稳定性测试还没做完，目前累计约 1 小时没有误报。
- 第三方检测网址只能帮你人工核对，不能证明每一条连接实际走的出口。

## 许可证

本项目使用 [MIT](LICENSE) 许可证。安装包里第三方组件的许可证放在 `packaging/licenses/`。
