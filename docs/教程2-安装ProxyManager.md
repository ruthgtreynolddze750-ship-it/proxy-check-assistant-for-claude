# 教程 2：安装 Proxy Manager 并建好代理端口

**目的**：在本机运行 Bright Data Proxy Manager，用它开一个本机代理端口（例如 `127.0.0.1:24000`），让 Claude 桌面端和专用 Chrome 都通过这个端口走 ISP 代理。

> 下面是 2026 年 11 月对照官方文档整理的步骤，以官网为准：[Proxy Manager 配置](https://docs.brightdata.com/products/proxy-manager/configuration)、[Proxy Manager 接入说明](https://docs.brightdata.com/products/proxy-manager/integration)。

## 一、下载指定版本（重要）

本助手的“管理器核验”目前**只支持 1.679.135 版**，会用它核对安装包和程序文件的校验值。用其他版本，管理器核验会一直显示“未确认”。

1. 打开官方发布页：<https://github.com/luminati-io/luminati-proxy/releases/tag/v1.679.135>
2. 下载 `luminati-proxy-manager-v1.679.135-setup.exe`，约 133 MB。
3. **下载好的安装包请保留**，教程 3 核验管理器时要用到它。

官方建议电脑至少有 4 GB 内存、2 核 CPU、3 GB 可用磁盘空间。

## 二、安装并登录

1. 双击安装包，按提示完成安装。
2. 打开 Proxy Manager，它会在浏览器里打开管理页面，默认地址是 `http://127.0.0.1:22999`。这个 **22999** 就是“管理端口”。
3. 在管理页面里登录你的 Bright Data 账号。

## 三、为 ISP 代理建一个端口

1. 在管理页面点 **Add new proxy**（新增代理端口）。
2. 选择你在教程 1 建好的 ISP 代理（zone），其他设置按需要选择。如果有“会话 / 固定 IP”之类的选项，选能保持同一个 IP 的那一项。
3. 点 **Save**。列表里会出现一个新端口，通常是 **24000** 起的数字，这个就是“代理端口”。
4. 记下两个数字：**管理端口**（如 22999）和**代理端口**（如 24000）。

本机程序连接 `127.0.0.1:代理端口` 时**不需要填用户名和密码**，因为 Proxy Manager 已经替你完成了认证。

## 四、自己先核对一次出口

1. 在 Proxy Manager 里找到这个端口的请求日志或测试功能，确认出口 IP 就是教程 1 记下的那个 IP。
2. 不一致时，先回到 Proxy Manager 和 Bright Data 控制台排查，**别急着用 Claude**。

## 避坑提醒

- 不要升级 Proxy Manager，除非本助手已经支持新版本，否则管理器核验会显示“未确认”。它弹出“是否下载新版本”“退出时安装 / 立即安装”时，都不要点安装。
- Proxy Manager 要一直开着。它关了，代理端口也就停了，助手的检测会失败。

下一步：[教程 3：助手首次配置与使用](教程3-助手配置与使用.md)
