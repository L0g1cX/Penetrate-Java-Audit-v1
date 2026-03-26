import os
import zipfile
import javalang
import networkx as nx
from io import BytesIO

class JavaAuditEngine:

    def __init__(self):
        # 核心数据结构：有向图 G
        self.G = nx.DiGraph()
        self.file_count = 0
        self.errors = 0
        self.file_list = []  # 用于存储项目文件结构
        self.class_sources = {}  # 用于存储类名对应的完整源码
        
        # 核心 Sink 预警规则 (优化版：减少泛匹配误报，补充脚本 RCE)
        self.VULN_RULES = {
            "RCE命令执行": [
                ".exec", "ProcessBuilder", # 去掉 Runtime 前缀，直接匹配 .exec
                "eval", "evaluate", "getValue", 
                "executeScript", "runScript"
            ],
            "SQL注入": [
                "executeQuery", "executeUpdate", "executeBatch", 
                "JdbcTemplate.query", "selectList", "createStatement" # 删除了过于宽泛的 "execute"
            ],
            "反序列化": ["readObject", "JSON.parseObject", "ObjectMapper.readValue", "XStream.fromXML"],
            "XXE": ["DocumentBuilder.parse", "SAXReader.read", "XMLReader.parse"],
            "SSRF": ["URL.openConnection", "HttpClient.execute", "OkHttpClient.newCall"],
            "路径遍历": ["FileInputStream", "FileOutputStream", "Paths.get"],
            "表达式注入": ["parseExpression", "Ognl.getValue"],
            "JNDI/Log4Shell": ["Context.lookup", "InitialDirContext.lookup", "logger.error", "logger.info"]
        }

    def _extract_calls(self, source_code):
        """核心解析逻辑：提取调用关系 + 轻量级局部符号表（精准类型推断）"""
        try:
            tree = javalang.parse.parse(source_code)
            for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                class_name = class_node.name
                for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                    class_name = class_node.name
                    # 保存当前类的源码，供后续 AI 审计使用
                    self.class_sources[class_name] = source_code 

                # 1. 建立类级别的“符号表” (捕获成员变量类型)
                field_types = {}
                for _, field_node in class_node.filter(javalang.tree.FieldDeclaration):
                    if hasattr(field_node.type, 'name'):
                        type_name = field_node.type.name
                        for declarator in field_node.declarators:
                            field_types[declarator.name] = type_name
                
                for _, method_node in class_node.filter(javalang.tree.MethodDeclaration):
                    caller = f"{class_name}.{method_node.name}"
                    self.G.add_node(caller, label=method_node.name, class_parent=class_name)
                    
                    # 2. 建立方法级别的“符号表” (捕获局部变量类型)
                    local_types = {}
                    for _, local_node in method_node.filter(javalang.tree.LocalVariableDeclaration):
                        if hasattr(local_node.type, 'name'):
                            type_name = local_node.type.name
                            for declarator in local_node.declarators:
                                local_types[declarator.name] = type_name
                    
                    # 3. 解析方法调用，并使用符号表进行精准还原
                    for _, inv in method_node.filter(javalang.tree.MethodInvocation):
                        qualifier = inv.qualifier
                        if qualifier:
                            # 优先级 1：查局部变量字典
                            if qualifier in local_types:
                                qualifier = local_types[qualifier]
                            # 优先级 2：查类成员变量字典
                            elif qualifier in field_types:
                                qualifier = field_types[qualifier]
                            # 优先级 3：最后的兜底猜想（首字母大写）
                            elif qualifier[0].islower():
                                qualifier = qualifier[0].upper() + qualifier[1:]
                        else:
                            # 如果没有 qualifier (直接调用)，则默认是当前类
                            qualifier = class_name
                            
                        callee = f"{qualifier}.{inv.member}"
                        self.G.add_edge(caller, callee)
        except Exception as e:
            self.errors += 1

    def scan_danger_sinks(self):
        alerts = []
        for node in self.G.nodes:
            # node 可能是 "Runtime.getRuntime.exec" 或 "SomeClass.exec"
            for vuln_type, keywords in self.VULN_RULES.items():
                for keyword in keywords:
                    # 💡 改进：如果是以点开头的关键词（如 .exec），检查节点是否以该后缀结尾
                    if keyword.startswith(".") and node.lower().endswith(keyword.lower()):
                        match = True
                    # 如果是普通关键词，执行原有的包含逻辑
                    elif keyword.lower() in node.lower():
                        match = True
                    else:
                        match = False

                    if match:
                        callers = list(self.G.predecessors(node))
                        alerts.append({
                            "漏洞类型": vuln_type,
                            "危险节点 (Sink)": node,
                            "匹配特征": keyword,
                            "上游调用数": len(callers),
                        })
                        break
        return alerts
    
    def scan_directory(self, path):
        """模式 A：扫描本地已存在的项目文件夹"""
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".java"):
                    self.file_count += 1
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        self._extract_calls(f.read())
        return self.G

    def scan_zip(self, zip_bytes):
        """模式 B：接收 Streamlit 上传的 ZIP 文件流"""
        self.file_list = [] # 每次上传清空旧数据
        with zipfile.ZipFile(BytesIO(zip_bytes)) as z:
            for info in z.infolist():
                self.file_list.append(info.filename) # 记录路径以供生成目录树
                if info.filename.endswith(".java"):
                    self.file_count += 1
                    with z.open(info) as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        self._extract_calls(content)
        return self.G

    def find_gadget_chain(self, start_node, end_node):
        """智慧搜索：自动寻找两个方法之间的利用链"""
        try:
            return nx.shortest_path(self.G, source=start_node, target=end_node)
        except nx.NetworkXNoPath:
            return None

    def get_summary(self):
        """返回扫描统计数据"""
        return {
            "total_files": self.file_count,
            "total_methods": self.G.number_of_nodes(),
            "total_calls": self.G.number_of_edges(),
            "parse_errors": self.errors,
            "file_list": self.file_list
        }