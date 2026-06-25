# 校园网自动登录

该脚本用于自动登录校园网认证门户 `http://172.19.1.1/`。

## 使用方法

### 1. 复制配置模板

```powershell
Copy-Item .env.example .env
```

### 2. 编辑 `.env`

填写校园网账号和密码：

```text
CAMPUS_USERNAME=你的账号
CAMPUS_PASSWORD=你的密码
```

### 3. 检测登录页面字段（不提交登录）

```powershell
python auto_login.py --dry-run
```

### 4. 执行登录

填写好 `.env` 后
```powershell
python auto_login.py
```

---

## 自动重连监控

```powershell
python monitor_login.py
```

默认检测间隔为 10 分钟：

```text
MONITOR_INTERVAL=600
```

日志默认保存到 `monitor.log`。

后台隐藏运行可使用 `start_monitor.vbs`。

---

## 网络说明

`172.19.1.1` 是校园网内网认证地址。

如果电脑当前仅使用手机热点联网，通常无法访问该地址。

建议先配置好 `.env`，再连接校园 Wi‑Fi 后运行 `run_login.bat`。

---

## 针对 JavaScript 登录页面

如果登录页面中没有 HTML `<form>` 表单，脚本也会自动扫描表单外部输入框。

如果认证系统通过 AJAX 提交登录请求：

1. 打开开发者工具（F12）
2. 打开 Network（网络）面板
3. 手动登录一次
4. 找到登录请求 URL
5. 填入：

```text
CAMPUS_SUBMIT_URL
```

---

## 调试：保存登录页面源码

```powershell
python auto_login.py --dry-run --dump-html login-page.html
```

---

## 针对完全由 JavaScript 渲染的认证页面

```powershell
python auto_login.py --dry-run --scan-assets --dump-assets portal-assets
```

该命令会下载并保存相关脚本资源，方便分析认证流程。

---

## 文件说明

| 文件 | 说明 |
|------|------|
| auto_login.py | 执行校园网登录 |
| monitor_login.py | 自动检测并重新登录 |
| .env | 用户配置文件 |
| .env.example | 配置模板 |
| start_monitor.vbs | 后台隐藏运行 |
| monitor.log | 运行日志 |
