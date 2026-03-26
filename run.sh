#!/bin/bash

# 设置脚本为遇到错误时立即退出
set -e

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 清屏（可选，取决于你的需求）
clear

# 打印标题
echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}                    Penetrate Java 审计工具${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. 检查 Python
echo -e "${YELLOW}[*] 正在检查 Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] 错误: 未检测到 python3，请先安装并添加到环境变量。${NC}"
    read -p "按 Enter 键退出..." dummy
    exit 1
fi
echo -e "${GREEN}[+] Python3 已找到。${NC}"

# 2. 检查 pip
echo -e "${YELLOW}[*] 正在检查 pip...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] 错误: 未检测到 pip3。请安装 python3-pip 包。${NC}"
    read -p "按 Enter 键退出..." dummy
    exit 1
fi
echo -e "${GREEN}[+] Pip3 已找到。${NC}"

# 3. 更新依赖
echo -e "${YELLOW}[*] 正在检查并更新必要依赖库...${NC}"
# 使用清华源
pip3 install streamlit javalang networkx pandas streamlit-agraph openai -i https://pypi.tuna.tsinghua.edu.cn/simple

# 4. 检查关键文件
echo -e "${YELLOW}[*] 正在检查关键文件...${NC}"
if [ ! -f "app.py" ]; then
    echo -e "${RED}[!] 错误: 未找到 app.py，请确保脚本在工具根目录下。${NC}"
    read -p "按 Enter 键退出..." dummy
    exit 1
fi
echo -e "${GREEN}[+] app.py 已找到。${NC}"

# 5. 启动工具
echo -e "${GREEN}[*] 环境检查完毕，正在启动沙盘编排界面...${NC}"
python3 -m streamlit run app.py

# 提示用户按任意键退出（在 Linux 中，通常不这么做，因为脚本会在 streamlit 退出后自然结束）
# 但如果你希望保持终端窗口打开，可以取消下面一行的注释
# read -p "按 Enter 键退出..." dummy