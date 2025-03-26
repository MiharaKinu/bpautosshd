#!/bin/bash
set -e

echo "开始编译..."
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

pyinstaller --onefile -n bpautosshd main.py || { echo "编译失败"; exit 1; }

echo -e "\033[32m[✓] 编译完成\033[0m"
echo "输出目录: $(pwd)/dist/bpautosshd"