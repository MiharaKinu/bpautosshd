# bpautosshd SSH爆破防御工具

一个自动从系统日志中提取失败SSH登录IP并使用UFW进行拉黑/解封的工具。

当发现sshd登录日志中出现失败登录尝试时，自动将其IP地址添加到UFW防火墙的黑名单中。

> 我们假设你每次都证书登录，不会出现登录失败的情况，更不会去登录那些不存在的用户。

需要你开启服务器的证书登录，一旦尝试登录出错，执行此脚本将直接封锁IP（但支持白名单方式），一旦误封锁，在云服务器上采取VNC登录，然后执行下列命令解封你的IP：

```bash
ufw delete allow from <ip>
```

## 功能特点

- 自动分析系统日志文件（默认为`/var/log/auth.log`）
- 提取失败SSH登录尝试的IP地址
- 使用UFW防火墙自动拉黑这些IP地址
- 支持白名单功能，避免误拉黑特定IP
- 支持解封功能，可以解除对特定IP的封禁
- 支持自定义日志文件路径
- 提供详细的操作统计信息

## 安装

### 依赖

- Python 3.x
- UFW (Uncomplicated Firewall)
- 系统需要有sudo权限以执行UFW命令

### 从源码安装

1. 克隆或下载本仓库

2. 安装依赖

```bash
pip install -r requirements.txt
```

3. 直接运行脚本

```bash
python main.py scan
```

### 编译为可执行文件

可以使用提供的build.sh脚本将程序编译为单一可执行文件：

```bash
chmod +x build.sh
./build.sh
```

编译后的可执行文件将位于`dist/bpautosshd`目录下。

## 使用方法

### 基本用法

```bash
# 扫描日志并拉黑失败登录的IP
python main.py scan

# 或者使用编译后的可执行文件
./dist/bpautosshd scan
```

### 解封IP

```bash
# 解封在日志中出现且已被拉黑的IP
python main.py clear

# 或者使用编译后的可执行文件
./dist/bpautosshd clear
```

### 高级选项

```bash
# 指定自定义日志文件路径
python main.py scan -C /var/log/syslog

# 添加白名单IP（多个IP用空格分隔）
python main.py scan -w 192.168.1.100 10.0.0.1

# 组合使用
python main.py scan -C /var/log/syslog -w 192.168.1.100
```

## 日志格式支持

本工具支持以下格式的失败登录日志：

1. `Invalid user xxx from IP port xxx`
2. `Failed password for invalid user xxx from IP port xxx ssh2`
3. `pam_unix(sshd:auth): authentication failure; ... rhost=IP`

## 许可证

本项目采用MIT许可证。详见[LICENSE](LICENSE)文件。

```
MIT License

Copyright (c) 2025 MiharaKinu
```