@echo off
chcp 65001 >nul
title Penetrate Java  - 启动器
color 0A

echo ======================================================
echo                                           Penetrate Java 审计工具
echo ======================================================

:: 1. 检查 Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 错误: 未检测到 Python，请先安装并添加到环境变量。
    pause
    exit
)

:: 2. 更新依赖
echo [*] 正在检查并更新必要依赖库...
pip install streamlit javalang networkx pandas streamlit-agraph openai -i https://pypi.tuna.tsinghua.edu.cn/simple

:: 3. 检查关键文件
if not exist "app.py" (
    echo [!] 错误: 未找到 app.py，请确保脚本在工具根目录下。
    pause
    exit
)

:: 4. 启动工具
echo [*] 环境检查完毕，正在启动界面...
streamlit run app.py

pause