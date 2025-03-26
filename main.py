import argparse
import subprocess
import os
from collections import deque
import re

def tail_f(file_path, lines=6000):
    """
    倒着读取日志文件的最后 `lines` 行。
    """
    try:
        with open(file_path, 'r') as f:
            return deque(f, maxlen=lines)
    except FileNotFoundError:
        print(f"[ERROR] 文件 {file_path} 不存在。")
        return []

def extract_failed_ips(log_lines):
    """
    从日志中提取失败的登录 IP（Invalid user 或密码错误）。
    支持以下格式：
    1. Invalid user xxx from IP port xxx
    2. Failed password for invalid user xxx from IP port xxx ssh2
    3. pam_unix(sshd:auth): authentication failure; ... rhost=IP
    """
    failed_ips = set()
    for line in log_lines:
        try:
            if "Invalid user" in line:
                # 处理 Invalid user 的情况
                parts = line.split()
                from_index = parts.index("from")
                if from_index + 1 < len(parts):
                    ip = parts[from_index + 1]
                    failed_ips.add(ip)
            elif "Failed password" in line:
                parts = line.split()
                from_index = parts.index("from")
                port_index = parts.index("port")
                if from_index + 1 < port_index:
                    ip = parts[from_index + 1]
                    failed_ips.add(ip)
            elif "authentication failure" in line and "rhost=" in line:
                rhost_part = [p for p in line.split() if p.startswith("rhost=")][0]
                ip = rhost_part.split("=")[1]
                failed_ips.add(ip)
        except (ValueError, IndexError):
            continue
    return failed_ips

def get_ufw_blacklist():
    """
    获取 UFW 当前的黑名单 IP 列表
    """
    try:
        result = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True, check=True)
        lines = result.stdout.split('\n')
        blacklist = set()
        
        for line in lines:
            if "DENY" in line:
                # 使用正则表达式匹配 IP 地址
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match:
                    blacklist.add(match.group(1))
        
        return blacklist
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] 无法获取 UFW 状态：{e}")
        return set()
    except Exception as e:
        print(f"[ERROR] 获取黑名单时发生未知错误：{e}")
        return set()

def block_ip(ip, blacklist):
    """
    使用 `ufw` 命令拉黑指定 IP。
    """
    if ip in blacklist:
        return False
        
    try:
        command = ["sudo", "ufw", "deny", "from", ip]
        subprocess.run(command, check=True)
        print(f"[+] 成功拉黑 IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] 拉黑失败 IP: {ip} ({e})")
        return False
    except Exception as e:
        print(f"[-] 未知错误 IP: {ip} ({e})")
        return False

def is_ip_whitelisted(ip, whitelist):
    """
    检查 IP 是否在白名单中。
    """
    return ip in whitelist

def unblock_ip(ip):
    """
    使用 `ufw` 命令解封指定 IP。
    """
    try:
        command = ["sudo", "ufw", "delete", "deny", "from", ip]
        subprocess.run(command, check=True)
        print(f"[+] 成功解封 IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] 解封失败 IP: {ip} ({e})")
        return False
    except Exception as e:
        print(f"[-] 未知错误 IP: {ip} ({e})")
        return False

def main():
    # 设置命令行参数
    parser = argparse.ArgumentParser(description="从日志中提取失败的 SSH 登录行为并自动拉黑/解封 IP。")
    parser.add_argument("action", nargs="?", choices=["scan", "clear"], help="执行操作：scan（扫描并拉黑）或 clear（解封检测到的 IP）")
    parser.add_argument("-C", "--config", default="/var/log/auth.log", help="指定日志文件路径，默认使用 /var/log/auth.log")
    parser.add_argument("-w", "--whitelist", nargs="+", default=[], help="指定白名单 IP，可以添加多个，用空格分隔")
    args = parser.parse_args()

    # 如果没有指定操作，显示帮助信息
    if not args.action:
        parser.print_help()
        return

    log_file = args.config
    whitelist = set(args.whitelist)

    # 检查是否有权限读取日志文件
    if not os.access(log_file, os.R_OK):
        print(f"[-] 无法读取日志文件 {log_file}，请确保脚本具有足够权限。")
        return

    # 读取日志并提取失败的登录 IP
    log_lines = tail_f(log_file, lines=6000)
    if not log_lines:
        print("[-] 日志文件为空或无法读取。")
        return

    failed_ips = extract_failed_ips(log_lines)
    if not failed_ips:
        print("[*] 未发现失败登录的 IP。")
        return

    # 获取当前 UFW 黑名单
    blacklist = get_ufw_blacklist()

    # 如果是 clear 命令，执行解封操作
    if args.action == "clear":
        print("\n" + "="*50)
        print("🔓 开始解封检测到的失败登录 IP")
        print("="*50 + "\n")

        # 找出需要解封的 IP（在黑名单中的失败登录 IP）
        to_unblock = failed_ips.intersection(blacklist)
        
        if not to_unblock:
            print("[*] 没有需要解封的 IP。")
            return

        print(f"[*] 发现 {len(to_unblock)} 个需要解封的 IP")
        
        # 统计数据
        success_count = 0
        failed_count = 0

        # 解封指定的 IP
        for ip in to_unblock:
            if unblock_ip(ip):
                success_count += 1
            else:
                failed_count += 1

        # 打印统计结果
        print("\n" + "="*50)
        print("📊 解封结果统计")
        print("="*50)
        print(f"✨ 需要解封的 IP 总数：{len(to_unblock)}")
        print(f"✅ 成功解封：{success_count}")
        print(f"❌ 解封失败：{failed_count}")
        print("="*50 + "\n")
        return

    print("\n" + "="*50)
    print("🔍 开始分析失败登录记录")
    print("="*50 + "\n")

    if whitelist:
        print(f"[*] 当前白名单 IP：{', '.join(whitelist)}")

    # 检查是否有权限读取日志文件
    if not os.access(log_file, os.R_OK):
        print(f"[-] 无法读取日志文件 {log_file}，请确保脚本具有足够权限。")
        return

    print(f"[*] 正在读取日志文件：{log_file}")

    # 倒着读取日志文件的最后 6000 行
    log_lines = tail_f(log_file, lines=6000)

    if not log_lines:
        print("[-] 日志文件为空或无法读取。")
        return

    # 提取失败的登录 IP
    failed_ips = extract_failed_ips(log_lines)

    if not failed_ips:
        print("[*] 未发现需要拉黑的 IP。")
        return

    # 获取当前 UFW 黑名单
    print("[*] 正在获取当前 UFW 黑名单...")
    blacklist = get_ufw_blacklist()
    if blacklist:
        print(f"[*] 当前黑名单包含 {len(blacklist)} 个 IP\n")

    # 统计数据
    total_ips = len(failed_ips)
    blocked_count = 0
    skipped_whitelist = 0
    skipped_blacklist = 0

    # 拉黑 IP（添加白名单和黑名单检查）
    for ip in failed_ips:
        if is_ip_whitelisted(ip, whitelist):
            skipped_whitelist += 1
            continue
        if ip in blacklist:
            skipped_blacklist += 1
            continue
        if block_ip(ip, blacklist):
            blocked_count += 1

    # 打印统计结果
    print("\n" + "="*50)
    print("📊 执行结果统计")
    print("="*50)
    print(f"✨ 检测到失败登录 IP 总数：{total_ips}")
    print(f"✅ 成功拉黑：{blocked_count}")
    print(f"⏭️  跳过白名单 IP：{skipped_whitelist}")
    print(f"⏭️  跳过已拉黑 IP：{skipped_blacklist}")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
