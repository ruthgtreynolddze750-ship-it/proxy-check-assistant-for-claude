# 教程 1：购买并创建 Bright Data ISP 代理

**目的**：拿到一个固定的 ISP 出口 IP，后面给 Proxy Manager 和本助手使用。

> 下面是 2026 年 11 月对照 Bright Data 官方文档整理的步骤。网站界面会改版，一切以官网当时显示为准：[ISP 代理快速入门](https://docs.brightdata.com/products/isp/quickstart)。

## 步骤

1. **注册并登录** [Bright Data](https://brightdata.com/)。
   - 如果用个人邮箱注册、账户里还没有付款方式，创建代理时会要求先添加付款方式。按官方说明，这一步是为了验证身份。
   - 请自己了解并遵守 Bright Data 的实名审核（KYC）和使用条款。
2. 左侧菜单 **Proxies → Create Proxy**，选择 **ISP**，点 **Continue**。
3. **填写代理名称**（创建后不能改名），按需要选择 IP 数量和国家/地区，再点 **Create Proxy**。
4. 创建完成后，在该代理的详情页里能看到：
   - **分配到的 IP**：记下你打算使用的那一个，它就是后面要填的“预期出口 IP”；
   - **访问信息**（主机、端口、用户名、密码）：只在 Proxy Manager 里登录 Bright Data 账号时用到，**不要**填进本助手。

## 避坑提醒

- 建议给 Claude 专门使用 1 个固定 IP，不要选轮换（Rotating）类型，也不要和别的用途混用。
- 账号密码只在 Bright Data 官网和 Proxy Manager 里使用，不要截图发给别人，也不要写进任何配置文件。

下一步：[教程 2：安装 Proxy Manager](教程2-安装ProxyManager.md)
