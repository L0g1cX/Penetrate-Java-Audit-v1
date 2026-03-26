import streamlit as st
from core_parser import JavaAuditEngine
import pandas as pd
from streamlit_agraph import agraph, Node, Edge, Config
from openai import OpenAI
from storage import save_settings, load_settings, save_workspace, load_workspace

st.set_page_config(page_title="Penetrate Java 审计助手", layout="wide")
st.markdown('<span style="color: grey; font-size: 16px;">该工具仅用于学习用途或合法测试，请注意保密规则</span>', unsafe_allow_html=True)

# --- 状态初始化 ---
# 1. 基础状态防御性初始化 (确保变量一定存在)
core_defaults = {
    'graph_ready': False,
    'selected_node': None,
    'search_query': "",
    'node_status': {},
    'sandbox_nodes': set(),
    'sandbox_edges': set(),
    'sandbox_notes': {},
    'graph_key': 0
}

for key, val in core_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

# 2. 引擎初始化
if 'engine' not in st.session_state:
    st.session_state.engine = JavaAuditEngine()

# 3. 自动加载配置 (从本地 config.json)
if 'setting_api_key_loaded' not in st.session_state:
    cfg = load_settings()
    st.session_state.setting_api_url = cfg.get("setting_api_url", "https://api.moonshot.cn/v1")
    st.session_state.setting_api_key = cfg.get("setting_api_key", "")
    st.session_state.setting_model_name = cfg.get("setting_model_name", "kimi-latest")
    st.session_state.setting_auto_suspicious = cfg.get("setting_auto_suspicious", False)
    st.session_state.setting_api_key_loaded = True

# 4. 自动加载进度 (从本地 workspace.json)
if 'workspace_loaded' not in st.session_state:
    ws = load_workspace()
    if ws:
        # 使用 update 保持引用或直接覆盖
        st.session_state.node_status = ws.get("node_status", {})
        st.session_state.sandbox_nodes = ws.get("sandbox_nodes", set())
        st.session_state.sandbox_edges = ws.get("sandbox_edges", set())
        st.session_state.sandbox_notes = ws.get("sandbox_notes", {})
    st.session_state.workspace_loaded = True

def render_tree(paths):
    tree = {}
    for path in paths:
        parts = path.strip("/").split("/")
        current = tree
        for part in parts:
            current = current.setdefault(part, {})
    
    def walk(node, depth=0):
        res = ""
        for name, child in sorted(node.items()):
            res += "  " * depth + "└── " + name + "\n"
            res += walk(child, depth + 1)
        return res
    return walk(tree)

# 跳转回调函数
def jump_to_node(node_name):
    # 核心修复：如果传入的名字带圆点，先洗干净
    clean_name = node_name.replace("🟢 ", "").replace("🟡 ", "").replace("🔴 ", "").replace("⚪ ", "")
    st.session_state.search_query = "" 
    st.session_state.selected_node = clean_name  # 存储干净的名字
    st.session_state['_node_selector'] = clean_name

# 状态设置回调
def set_node_status(node_name, status):
    st.session_state.node_status[node_name] = status

def add_to_sandbox(node_name):
    st.session_state.sandbox_nodes.add(node_name)
    st.toast(f"已将 {node_name} 加入画布！", icon="✨")

# 状态显示辅助函数
def get_node_display(node_name):
    status = st.session_state.node_status.get(node_name, "unknown")
    if status == "safe":
        return f"🟢 {node_name}"
    elif status == "suspicious":
        return f"🟡 {node_name}"
    elif status == "vuln":
        return f"🔴 {node_name}"
    else:
        return f"⚪ {node_name}"

# 获取画布节点颜色
def get_canvas_color(node_name):
    status = st.session_state.node_status.get(node_name, "unknown")
    if status == "safe": return "#A7F3D0"       # 浅绿
    elif status == "suspicious": return "#FDE68A" # 浅黄
    elif status == "vuln": return "#FECACA"      # 鲜红
    return "#E5E7EB" # 默认灰白

st.title("🛡️ Penetrate Java 审计助手")

with st.sidebar:
    st.header("项目管理")
    uploaded_file = st.file_uploader("上传项目 ZIP 源码包", type="zip")
    
    if uploaded_file is not None and not st.session_state.graph_ready:
        with st.spinner("正在分析项目文件..."):
            # 💡 核心修复：只读取一次，并存入变量
            zip_bytes = uploaded_file.read() 
            st.session_state.engine.scan_zip(zip_bytes)
            
            # 自动标记逻辑
            if st.session_state.get("setting_auto_suspicious"):
                alerts = st.session_state.engine.scan_danger_sinks()
                for alert in alerts:
                    node_name = alert['危险节点 (Sink)']
                    if node_name not in st.session_state.node_status:
                        st.session_state.node_status[node_name] = "suspicious"
            
            st.session_state.graph_ready = True
            st.success("分析完成！")

    if st.session_state.graph_ready:
        stats = st.session_state.engine.get_summary()
        
        with st.expander("📁 项目目录结构", expanded=True):
            st.code(render_tree(stats['file_list']), language="text")
            
        st.divider()
        st.markdown(f"**已解析文件:** {stats['total_files']} 个")
        st.markdown(f"**提取方法节点:** {stats['total_methods']} 个")
        st.markdown(f"**识别调用链路:** {stats['total_calls']} 条")
        
        st.write("")
        if st.button("清空并重新上传"):
            st.session_state.engine = JavaAuditEngine()
            st.session_state.graph_ready = False
            st.session_state.node_status = {} # 清空标记状态
            st.rerun()

if st.session_state.graph_ready:
    # 🌟 核心升级：加入第四个标签页
    tab_alerts, tab_context, tab_links, tab_sandbox, tab_settings = st.tabs([
        "🚨 危险特征匹配", 
        "🔍 节点关系", 
        "🕸️ 全局调用链路",
        "🎨 我的画布",
        "⚙️ 设置"
    ])

    # ================== 标签页 1：危险特征 ==================
    with tab_alerts:
        alerts = st.session_state.engine.scan_danger_sinks()
        if alerts:
            actionable_alerts = [a for a in alerts if a['上游调用数'] > 0]
            st.warning(f"发现 **{len(alerts)}** 个潜在风险点！其中 **{len(actionable_alerts)}** 个已被调用。")
            h1, h2, h3, h4, h5 = st.columns([0.5, 1.5, 4, 1.5, 1.5])
            h1.markdown("**#**"); h2.markdown("**漏洞类型**"); h3.markdown("**危险节点 (Sink)**")
            h4.markdown("**匹配特征**"); h5.markdown("**操作**")
            st.markdown("---")
            for i, alert in enumerate(alerts, start=1):
                c1, c2, c3, c4, c5 = st.columns([0.5, 1.5, 4, 1.5, 1.5])
                c1.write(str(i)); c2.write(alert['漏洞类型'])
                c3.markdown(f"`{get_node_display(alert['危险节点 (Sink)']).replace('⚪ ', '')}`") 
                c4.code(alert['匹配特征'])
                if alert['上游调用数'] > 0:
                    c5.button("追查 🔗", key=f"trace_{i}_{alert['危险节点 (Sink)']}", on_click=jump_to_node, args=(alert['危险节点 (Sink)'],))
                else:
                    c5.write("孤立节点")
        else:
            st.success("🎉 当前项目中未匹配到已知的敏感高危特征。")

    # ================== 标签页 2：上下文分析面板 ==================
    with tab_context:
        col1, col2 = st.columns([1, 2])
        with col1:
            st.subheader("📦 项目类/方法树")
            all_nodes = list(st.session_state.engine.G.nodes)
            st.text_input("搜索方法名", key="search_query")
            search_val = st.session_state.search_query.lower()
            filtered_nodes = [node for node in all_nodes if search_val in node.lower()]
            sorted_nodes = sorted(list(set(filtered_nodes)))
            
            if not sorted_nodes:
                st.warning("未找到匹配的方法")
                selected_method = None
            else:
                current_target = st.session_state.get('selected_node', "")
                if current_target and current_target not in sorted_nodes:
                    sorted_nodes.append(current_target)
                    sorted_nodes = sorted(list(set(sorted_nodes)))
                try: default_idx = sorted_nodes.index(current_target)
                except ValueError: default_idx = 0
                    
                def on_selectbox_change():
                    st.session_state.selected_node = st.session_state._node_selector
                    
                selected_method = st.selectbox(
                    "选择一个节点作为分析起点", sorted_nodes, index=default_idx,
                    format_func=get_node_display, key="_node_selector", on_change=on_selectbox_change
                )
                st.session_state.selected_node = selected_method

        with col2:
            st.subheader("🔍 上下文分析")
            if selected_method:
                clean_node = selected_method.replace("🟢 ", "").replace("🟡 ", "").replace("🔴 ", "").replace("⚪ ", "")
                st.info(f"正在分析节点: **{get_node_display(clean_node)}**")
                
                # 🌟 新增：一键加入画布按钮
                btn_col1, btn_col2, btn_col3, btn_col4 = st.columns([1, 1, 1, 1.5])
                btn_col1.button("🟢 设为安全", on_click=set_node_status, args=(clean_node, "safe"), use_container_width=True)
                btn_col2.button("🟡 设为可疑", on_click=set_node_status, args=(clean_node, "suspicious"), use_container_width=True)
                btn_col3.button("🔴 设为漏洞", on_click=set_node_status, args=(clean_node, "vuln"), use_container_width=True)
                btn_col4.button("📍 加入编排画布", on_click=add_to_sandbox, args=(clean_node,), type="primary", use_container_width=True)
                st.write("") 
                
                try:
                    callers = sorted(list(set(st.session_state.engine.G.predecessors(clean_node))))
                    callees = sorted(list(set(st.session_state.engine.G.successors(clean_node))))
                except Exception:
                    callers, callees = [], []
                
                sub_tab1, sub_tab2 = st.tabs([f"逆向调用者 ({len(callers)})", f"正向被调用 ({len(callees)})"])
                with sub_tab1:
                    if callers:
                        hc1, hc2, hc3 = st.columns([0.5, 7, 2]); hc1.markdown("**#**"); hc2.markdown("**调用来源**"); hc3.markdown("**操作**"); st.markdown("---")
                        for i, caller in enumerate(callers, start=1):
                            c1, c2, c3 = st.columns([0.5, 7, 2])
                            c1.write(str(i)); c2.write(get_node_display(caller))
                            c3.button("跳转 🔗", key=f"caller_{i}_{caller}", on_click=jump_to_node, args=(caller,))
                    else: st.write("暂未发现上游调用。")
                with sub_tab2:
                    if callees:
                        hc1, hc2, hc3 = st.columns([0.5, 7, 2]); hc1.markdown("**#**"); hc2.markdown("**调用目标**"); hc3.markdown("**操作**"); st.markdown("---")
                        for i, callee in enumerate(callees, start=1):
                            c1, c2, c3 = st.columns([0.5, 7, 2])
                            c1.write(str(i)); c2.write(get_node_display(callee))
                            c3.button("跳转 🔗", key=f"callee_{i}_{callee}", on_click=jump_to_node, args=(callee,))
                    else: st.write("当前节点未发起进一步调用。")

    # ================== 标签页 3：全局调用链路 ==================
    with tab_links:
        st.subheader("🕸️ 全局调用链路总览")
        all_edges = list(st.session_state.engine.G.edges())
        if all_edges:
            edges_df = pd.DataFrame(all_edges, columns=["调用来源 (Caller)", "调用目标 (Callee)"])
            st.dataframe(edges_df, use_container_width=True, height=600)
        else: st.info("当前项目中未发现任何方法间的调用关系。")

    # ================== 标签页 4：利用链编排画布 ==================
    with tab_sandbox:
        st.subheader("🎨 利用链编排画布")
        
        # 1. 准备渲染数据 (先将节点组装好，方便传入字体配置)
        nodes, edges = [], []
        for node_name in st.session_state.sandbox_nodes:
            short_label = node_name.split('.')[-1] # 仅显示方法名，更简洁
            nodes.append(Node(
                id=node_name, 
                label=short_label, 
                size=25, 
                color=get_canvas_color(node_name),
                # 💡 新增：自定义 #666666 字体颜色
                font={"color": "#666666", "face": "sans-serif", "size": 16},
                title=f"备注: {st.session_state.sandbox_notes.get(node_name, '无')}"
            ))
        for src, tgt in st.session_state.sandbox_edges:
            edges.append(Edge(source=src, target=tgt, type="CURVE_SMOOTH"))

        jiggle = st.session_state.get('graph_key', 0) % 2
            
    # 2. 画布配置
        config = Config(
            width="100%", 
            height=600 + jiggle,  # 这里就是神来之笔：600 和 601 像素反复切换
            directed=True, 
            physics=False, 
            hierarchical=False, 
            nodeHighlightBehavior=True, 
            highlightColor="#F7A072",
            interaction={
                "zoomView": False,          # 禁用鼠标滚轮缩放
                "navigationButtons": True,  # 开启左下角的 +/- 缩放按钮
                "dragView": True            # 依然允许按住左键平移画布
            }
        )
            
        # 控制栏布局
        col_hint, col_refresh = st.columns([5, 1])
        with col_hint:
            st.markdown("💡 **操作提示**：点击节点进行编辑；使用边缘按钮缩放。")
        with col_refresh:
            if st.button("🔄 刷新", use_container_width=True):
                # 每次点击让计数器 +1
                st.session_state['graph_key'] = st.session_state.get('graph_key', 0) + 1
                st.rerun()

        # 3. 核心交互：直接正常渲染即可，1像素的高度差会解决所有问题
        with st.container(border=True):
            clicked_node = agraph(nodes=nodes, edges=edges, config=config)
            
        # 4. 模拟“悬浮窗”：节点编辑区 (仅在点击节点后显示)
        if clicked_node:
            with st.container(border=True):
                c1, c2, c3 = st.columns([2, 3, 1])
                with c1:
                    st.markdown(f"🎯 **正在编辑**: `{clicked_node.split('.')[-1]}`")
                    # 快速修改颜色状态
                    sc1, sc2, sc3 = st.columns(3)
                    if sc1.button("🟢", key="set_safe"): set_node_status(clicked_node, "safe"); st.rerun()
                    if sc2.button("🟡", key="set_susp"): set_node_status(clicked_node, "suspicious"); st.rerun()
                    if sc3.button("🔴", key="set_vuln"): set_node_status(clicked_node, "vuln"); st.rerun()
                with c2:
                    current_note = st.session_state.sandbox_notes.get(clicked_node, "")
                    new_note = st.text_input("编辑备注", value=current_note, key=f"note_{clicked_node}")
                    # 💡 修复：将未定义的 current_target 改为 current_note
                    if new_note != current_note:
                        st.session_state.sandbox_notes[clicked_node] = new_note
                with c3:
                    st.write("") # 对齐
                    if st.button("🗑️ 移除节点", type="primary", use_container_width=True):
                        st.session_state.sandbox_nodes.remove(clicked_node)
                        # 同时删除关联的边
                        st.session_state.sandbox_edges = {e for e in st.session_state.sandbox_edges if clicked_node not in e}
                        st.rerun()

        st.divider()

        # 5. 底部控制台：连接管理
        ctrl_col1, ctrl_col2 = st.columns([1, 1])
        with ctrl_col1:
            st.markdown("##### 🔗 建立新连接")
            if len(st.session_state.sandbox_nodes) >= 2:
                s_nodes = sorted(list(st.session_state.sandbox_nodes))
                src = st.selectbox("起点 (Caller)", s_nodes, key="new_edge_src")
                tgt = st.selectbox("终点 (Callee)", s_nodes, key="new_edge_tgt")
                if st.button("添加连线"):
                    st.session_state.sandbox_edges.add((src, tgt))
                    st.rerun()
            else: st.info("请先加入更多节点。")

        with ctrl_col2:
            st.markdown("##### ✂️ 断开已有连接")
            if st.session_state.sandbox_edges:
                edge_to_del = st.selectbox(
                    "选择要删除的边", 
                    list(st.session_state.sandbox_edges),
                    format_func=lambda x: f"{x[0].split('.')[-1]} ➡️ {x[1].split('.')[-1]}"
                )
                if st.button("确认切断连接"):
                    st.session_state.sandbox_edges.remove(edge_to_del)
                    st.rerun()
            else: st.write("当前无任何连线。")

        if st.button("🧹 清空整个画布"):
            st.session_state.sandbox_nodes.clear()
            st.session_state.sandbox_edges.clear()
            st.session_state.sandbox_notes.clear()
            st.rerun()
        # ================= AI 自动化审计模块 =================
        st.markdown("##### 🤖 发送给大模型处理")
        if st.button("✨ 智能审计画布链路", type="primary", use_container_width=True):
            if not st.session_state.sandbox_edges:
                st.warning("画布中还没有逻辑连线！请先排布好利用链。")
            elif not st.session_state.get("setting_api_key"):
                st.error("请先在【⚙️ 设置】标签页中配置 API 密钥！")
            else:
                with st.spinner("🧠 正在组装链路上下文，AI 正在分析源码，请稍候..."):
                    try:
                        # 1. 组装链路拓扑
                        chain_desc = "用户排布的调用链路如下：\n"
                        for src, tgt in st.session_state.sandbox_edges:
                            chain_desc += f"- {src} 调用了 {tgt}\n"
                        
                        # 2. 提取涉及的类源码
                        involved_classes = set()
                        for node in st.session_state.sandbox_nodes:
                            class_name = node.split('.')[0]
                            involved_classes.add(class_name)
                        
                        code_context = "\n".join([
                            f"=== 类 {cls} 源码 ===\n{st.session_state.engine.class_sources.get(cls, '未找到源码')}\n"
                            for cls in involved_classes
                        ])
                        
                        # 3. 组装 Prompt
                        system_prompt = "你是网络安全领域的顶尖专家，精通 Java 代码审计。请根据用户提供的调用链路和源码，分析是否存在安全漏洞（如 SQL注入、RCE 等），描述污点数据的传播路径，并尝试给出 PoC Payload 建议。"
                        user_prompt = f"{chain_desc}\n\n以下是链路涉及的类源码：\n{code_context}"
                        
                        # 4. 调用 API
                        client = OpenAI(
                            api_key=st.session_state["setting_api_key"],
                            base_url=st.session_state.get("setting_api_url", "https://api.moonshot.cn/v1")
                        )
                        response = client.chat.completions.create(
                            model=st.session_state.get("setting_model_name", "kimi-latest"),
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt}
                            ],
                            temperature=1
                        )
                        
                        # 5. 展示结果
                        st.success("审计完成！")
                        with st.expander("📝 查看 AI 深度审计报告", expanded=True):
                            st.markdown(response.choices[0].message.content)
                    
                    except Exception as e:
                        st.error(f"AI 调用失败，请检查设置或网络: {str(e)}")

    # ================== 标签页 5：设置 ==================
    with tab_settings:
        st.subheader("⚙️ 系统与设置")
        
        st.markdown("##### 🤖 大模型接入配置")
        
        # 💡 关键修改：增加 value=st.session_state.setting_xxx
        # 这样刷新时，组件会强制回显 session_state 里的旧值
        st.text_input("API 链接 (Base URL)", 
                     value=st.session_state.get("setting_api_url", "https://api.moonshot.cn/v1"), 
                     key="setting_api_url")
        
        st.text_input("API 密钥 (API Key)", 
                     type="password", 
                     value=st.session_state.get("setting_api_key", ""), 
                     key="setting_api_key")
        
        st.text_input("模型名称 (Model)", 
                     value=st.session_state.get("setting_model_name", "kimi-latest"), 
                     key="setting_model_name")
        
        st.markdown("##### ⚡ 自动化审计规则")
        st.checkbox("自动将匹配到【危险特征】的节点设为 🟡 可疑状态", 
                    value=st.session_state.get("setting_auto_suspicious", False), 
                    key="setting_auto_suspicious")
        
        # ... 其他代码保持不变 ...

        if st.button("💾 保存配置到本地", type="primary"):
            # 构造要保存的字典
            config_to_save = {
                "setting_api_url": st.session_state.setting_api_url,
                "setting_api_key": st.session_state.setting_api_key,
                "setting_model_name": st.session_state.setting_model_name,
                "setting_auto_suspicious": st.session_state.setting_auto_suspicious
            }
            # 调用 storage.py 里的函数（确保你已经 import 了它）
            save_settings(config_to_save)
            st.success("配置已同步至本地 config.json！")

else:
    st.info("💡 请在左侧上传项目的 ZIP 压缩包，开始分析项目结构。")