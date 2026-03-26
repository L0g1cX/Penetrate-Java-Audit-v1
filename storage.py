import json
import os

CONFIG_FILE = "config.json"
WORKSPACE_FILE = "workspace.json"

def save_settings(settings_dict):
    """保存全局配置（API、开关等）"""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings_dict, f, ensure_ascii=False, indent=4)

def load_settings():
    """读取全局配置"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_workspace(node_status, sandbox_nodes, sandbox_edges, sandbox_notes):
    """保存审计进度"""
    data = {
        "node_status": node_status,
        "sandbox_nodes": list(sandbox_nodes),
        # 元组不能直接存 JSON，需要转成列表
        "sandbox_edges": [list(e) for e in sandbox_edges],
        "sandbox_notes": sandbox_notes
    }
    with open(WORKSPACE_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def load_workspace():
    """加载审计进度"""
    if os.path.exists(WORKSPACE_FILE):
        with open(WORKSPACE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # 还原回 set 和 tuple 格式
            return {
                "node_status": data.get("node_status", {}),
                "sandbox_nodes": set(data.get("sandbox_nodes", [])),
                "sandbox_edges": set([tuple(e) for e in data.get("sandbox_edges", [])]),
                "sandbox_notes": data.get("sandbox_notes", {})
            }
    return None