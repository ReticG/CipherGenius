"""
CipherGenius Web Interface
基于Streamlit的密码学方案生成Web界面
"""

import sys
import io
import streamlit as st
from typing import Optional

# 只在需要时设置编码，避免Streamlit重新加载时出错
try:
    if sys.stdout and hasattr(sys.stdout, 'buffer') and not isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
except (ValueError, AttributeError):
    # Streamlit环境下可能已经设置好编码，忽略错误
    pass

from cipher_genius.core.parser import RequirementParser
from cipher_genius.core.generator import SchemeGenerator
from cipher_genius.core.simple_validator import quick_validate
from cipher_genius.core.scheme_detector import detect_scheme_type
from cipher_genius.knowledge.components import ComponentLibrary
from cipher_genius.codegen.generator import CodeGenerator


# 页面配置
st.set_page_config(
    page_title="CipherGenius - 密码学方案生成器",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 自定义CSS - 增强版
st.markdown("""
<style>
    /* 主标题样式 */
    .main-header {
        font-size: 3.5rem;
        font-weight: bold;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 1rem;
        animation: fadeIn 1s ease-in;
    }

    /* 副标题样式 */
    .sub-header {
        text-align: center;
        font-size: 1.2rem;
        color: #666;
        margin-bottom: 2rem;
        animation: fadeIn 1.5s ease-in;
    }

    /* 淡入动画 */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* 进度条 */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    }

    /* 组件卡片 - 增强版 */
    .component-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.2rem;
        border-radius: 12px;
        margin: 0.8rem 0;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .component-card:hover {
        transform: translateY(-3px) scale(1.02);
        box-shadow: 0 8px 12px rgba(0, 0, 0, 0.2);
    }

    /* 统计卡片 */
    .stat-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease;
    }

    .stat-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
    }

    .stat-number {
        font-size: 2.5rem;
        font-weight: bold;
        margin: 0.5rem 0;
    }

    .stat-label {
        font-size: 1rem;
        opacity: 0.9;
    }

    /* 成功框 - 增强版 */
    .success-box {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        border: none;
        padding: 1.2rem;
        border-radius: 12px;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        font-weight: 500;
    }

    /* 警告框 - 增强版 */
    .warning-box {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        border: none;
        padding: 1.2rem;
        border-radius: 12px;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        font-weight: 500;
    }

    /* 错误框 - 增强版 */
    .error-box {
        background: linear-gradient(135deg, #ee0979 0%, #ff6a00 100%);
        border: none;
        padding: 1.2rem;
        border-radius: 12px;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        font-weight: 500;
    }

    /* 信息框 */
    .info-box {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border: none;
        padding: 1.2rem;
        border-radius: 12px;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        font-weight: 500;
    }

    /* 侧边栏样式 */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }

    [data-testid="stSidebar"] .element-container {
        color: white;
    }

    /* 按钮增强 */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.3s ease;
    }

    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }

    /* 度量指标增强 */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: bold;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    /* Tab样式增强 */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 10px 20px;
        font-weight: 600;
    }

    /* 输入框增强 */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea {
        border-radius: 8px;
        border: 2px solid #e0e0e0;
        transition: all 0.3s ease;
    }

    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }

    /* 下载按钮样式 */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 2rem;
        font-weight: 600;
    }

    /* 代码块增强 */
    .stCodeBlock {
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """初始化session state"""
    if 'generated_schemes' not in st.session_state:
        st.session_state.generated_schemes = []
    if 'current_requirement' not in st.session_state:
        st.session_state.current_requirement = None
    if 'parsed_requirement' not in st.session_state:
        st.session_state.parsed_requirement = None
    if 'generation_history' not in st.session_state:
        st.session_state.generation_history = []
    if 'total_generations' not in st.session_state:
        st.session_state.total_generations = 0


def render_stats_dashboard():
    """渲染统计仪表板"""
    lib = ComponentLibrary()
    all_components = lib.list_all()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">🔐 总组件数</div>
            <div class="stat-number">{len(all_components)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        pq_count = sum(1 for c in all_components if any("post_quantum" in str(p).lower() or "quantum" in str(p).lower() for p in c.properties))
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">🔮 后量子算法</div>
            <div class="stat-number">{pq_count}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">📊 已生成方案</div>
            <div class="stat-number">{st.session_state.total_generations}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        categories = {}
        for comp in all_components:
            cat = str(comp.category)
            categories[cat] = categories.get(cat, 0) + 1
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">📚 组件类别</div>
            <div class="stat-number">{len(categories)}</div>
        </div>
        """, unsafe_allow_html=True)


def render_header():
    """渲染页面头部"""
    st.markdown('<h1 class="main-header">🔐 CipherGenius</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">'
        '基于大语言模型的智能密码学方案生成器 | v1.1.0 | 55个组件 | 支持后量子密码'
        '</p>',
        unsafe_allow_html=True
    )

    # 统计仪表板
    render_stats_dashboard()

    st.markdown("---")


def render_sidebar():
    """渲染侧边栏 - 增强版"""
    with st.sidebar:
        # 顶部logo和版本信息
        st.markdown("""
        <div style='text-align: center; padding: 1rem 0; color: white;'>
            <h1 style='margin: 0; font-size: 2rem;'>🔐</h1>
            <h3 style='margin: 0.5rem 0; color: white;'>CipherGenius</h3>
            <p style='margin: 0; opacity: 0.9; font-size: 0.9rem;'>v1.1.0</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # 组件库统计
        st.markdown("<h3 style='color: white;'>📚 组件库</h3>", unsafe_allow_html=True)

        lib = ComponentLibrary()
        all_components = lib.list_all()

        # 使用自定义卡片显示总数
        st.markdown(f"""
        <div style='background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center; margin: 1rem 0;'>
            <div style='font-size: 2.5rem; font-weight: bold; color: white;'>{len(all_components)}</div>
            <div style='color: white; opacity: 0.9;'>总组件数</div>
        </div>
        """, unsafe_allow_html=True)

        # 按类别统计
        categories = {}
        for comp in all_components:
            cat = str(comp.category)
            categories[cat] = categories.get(cat, 0) + 1

        st.markdown("<h4 style='color: white; margin-top: 1.5rem;'>组件分布</h4>", unsafe_allow_html=True)

        # 使用进度条显示分布
        max_count = max(categories.values())
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            st.markdown(f"<p style='color: white; margin: 0.3rem 0;'><strong>{cat}</strong>: {count}个</p>", unsafe_allow_html=True)
            st.progress(count / max_count)

        st.markdown("---")

        # 后量子算法亮点
        pq_comps = [c for c in all_components if any("post_quantum" in str(p).lower() or "quantum" in str(p).lower() for p in c.properties)]
        if pq_comps:
            st.markdown("""
            <div style='background: rgba(255,215,0,0.2); padding: 1rem; border-radius: 8px; border: 1px solid rgba(255,215,0,0.5); margin: 1rem 0;'>
                <div style='color: #FFD700; font-weight: bold; margin-bottom: 0.5rem;'>🔮 后量子密码支持</div>
                <div style='color: white; font-size: 0.9rem;'>
                    Kyber, Dilithium, SPHINCS+<br/>
                    抗量子计算机攻击
                </div>
            </div>
            """, unsafe_allow_html=True)

        # 示例需求
        st.markdown("<h3 style='color: white; margin-top: 1.5rem;'>💡 快速示例</h3>", unsafe_allow_html=True)

        examples = [
            ("🌐 IoT加密", "为IoT传感器数据提供256位安全的加密和认证"),
            ("🔑 API认证", "为Web API提供消息认证机制"),
            ("📱 密码存储", "为移动应用提供安全的密码哈希存储"),
            ("✍️ 数字签名", "为文档提供数字签名功能"),
            ("🔮 后量子", "为关键数据提供抗量子计算机攻击的加密和签名方案")
        ]

        for i, (label, example) in enumerate(examples, 1):
            if st.button(label, key=f"example_{i}", use_container_width=True):
                st.session_state.example_text = example

        st.markdown("---")

        # 底部信息
        st.markdown("""
        <div style='text-align: center; color: white; opacity: 0.7; font-size: 0.8rem; margin-top: 2rem;'>
            <p>基于大语言模型</p>
            <p>智能密码学方案生成</p>
            <p style='margin-top: 1rem;'>© 2025 CipherGenius</p>
        </div>
        """, unsafe_allow_html=True)


def render_input_section():
    """渲染需求输入区域"""
    st.header("📝 步骤 1: 输入需求")

    # 如果有示例文本，使用它
    default_text = st.session_state.get('example_text', '')

    requirement_text = st.text_area(
        "请用自然语言描述您的密码学需求：",
        value=default_text,
        height=120,
        placeholder="例如: 为IoT传感器数据提供256位安全的加密和认证",
        help="用简单的语言描述您需要什么样的密码学方案，包括安全级别、应用场景等"
    )

    # 高级选项
    with st.expander("⚙️ 高级选项"):
        num_variants = st.slider(
            "生成方案数量",
            min_value=1,
            max_value=5,
            value=1,
            help="生成多个不同的方案供选择"
        )

        generate_code = st.checkbox(
            "生成实现代码",
            value=True,
            help="自动生成Python和C代码实现"
        )

    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        generate_btn = st.button("🚀 生成方案", type="primary", use_container_width=True)

    with col2:
        clear_btn = st.button("🗑️ 清空", use_container_width=True)

    if clear_btn:
        st.session_state.generated_schemes = []
        st.session_state.current_requirement = None
        st.session_state.parsed_requirement = None
        if 'example_text' in st.session_state:
            del st.session_state.example_text
        st.rerun()

    return generate_btn, requirement_text, num_variants, generate_code


def render_scheme_type_detection(requirement_text: str):
    """渲染方案类型检测结果"""
    with st.spinner("🔍 检测方案类型..."):
        detected_type, confidence = detect_scheme_type(requirement_text)

    if detected_type:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.success(f"✅ 检测到类型: **{detected_type.value}**")
        with col2:
            st.metric("置信度", f"{confidence:.0%}")


def render_requirement_parsing(requirement_text: str):
    """渲染需求解析结果"""
    st.header("🔍 步骤 2: 需求分析")

    with st.spinner("⏳ 正在解析需求..."):
        parser = RequirementParser()
        parsed = parser.parse(requirement_text)
        st.session_state.parsed_requirement = parsed

    req = parsed.requirement

    # 显示解析结果
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "方案类型",
            req.scheme_type if isinstance(req.scheme_type, str) else req.scheme_type.value
        )

    with col2:
        st.metric("安全级别", f"{req.security.security_level} 位")

    with col3:
        st.metric("解析置信度", f"{parsed.confidence:.0%}")

    # 详细信息
    with st.expander("📋 查看详细解析结果", expanded=False):
        st.subheader("目标平台")
        st.write(f"- **类型**: {req.target_platform.type if isinstance(req.target_platform.type, str) else req.target_platform.type.value}")
        st.write(f"- **资源等级**: {req.target_platform.resource_level if isinstance(req.target_platform.resource_level, str) else req.target_platform.resource_level.value}")

        st.subheader("安全要求")
        st.write(f"- **安全级别**: {req.security.security_level}位")
        st.write(f"- **威胁模型**: {[t if isinstance(t, str) else t.value for t in req.security.threats]}")

        if parsed.ambiguities:
            st.warning("**歧义项:**")
            for amb in parsed.ambiguities:
                st.write(f"- {amb}")

        if parsed.assumptions:
            st.info("**假设条件:**")
            for assumption in parsed.assumptions:
                st.write(f"- {assumption}")


def render_scheme_generation(req, num_variants: int):
    """渲染方案生成结果 - 增强版"""
    st.header("⚙️ 步骤 3: 生成方案")

    # 进度跟踪
    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        # 初始化
        status_text.markdown('<div class="info-box">🔄 初始化方案生成器...</div>', unsafe_allow_html=True)
        progress_bar.progress(0.2)

        generator = SchemeGenerator()

        # 生成方案
        status_text.markdown(f'<div class="info-box">⚙️ 正在生成 {num_variants} 个方案...</div>', unsafe_allow_html=True)
        progress_bar.progress(0.4)

        schemes = generator.generate(req, num_variants=num_variants)

        progress_bar.progress(0.8)
        status_text.markdown('<div class="info-box">✨ 完善方案细节...</div>', unsafe_allow_html=True)

        st.session_state.generated_schemes = schemes

        # 更新统计
        if schemes:
            st.session_state.total_generations += len(schemes)
            # 添加到历史记录
            import datetime
            st.session_state.generation_history.append({
                'time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'count': len(schemes),
                'requirement': req.scheme_type if isinstance(req.scheme_type, str) else req.scheme_type.value
            })

        progress_bar.progress(1.0)

        if schemes:
            status_text.markdown(f'<div class="success-box">✅ 成功生成 {len(schemes)} 个方案！</div>', unsafe_allow_html=True)
            return schemes
        else:
            status_text.markdown('<div class="error-box">❌ 方案生成失败，请重试</div>', unsafe_allow_html=True)
            return []

    except Exception as e:
        progress_bar.progress(1.0)
        status_text.markdown(f'<div class="error-box">❌ 生成过程中出错: {str(e)}</div>', unsafe_allow_html=True)
        return []


def render_scheme_display(schemes: list, generate_code: bool):
    """渲染方案展示"""
    st.header("📊 步骤 4: 方案详情")

    # 使用tabs显示多个方案
    if len(schemes) == 1:
        render_single_scheme(schemes[0], generate_code)
    else:
        tabs = st.tabs([f"方案 {i+1}: {scheme.metadata.name}" for i, scheme in enumerate(schemes)])
        for i, (tab, scheme) in enumerate(zip(tabs, schemes)):
            with tab:
                render_single_scheme(scheme, generate_code, scheme_idx=i+1)


def render_single_scheme(scheme, generate_code: bool, scheme_idx: Optional[int] = None):
    """渲染单个方案"""

    # 方案概览
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("方案名称", scheme.metadata.name)

    with col2:
        st.metric("方案类型", scheme.metadata.scheme_type)

    with col3:
        st.metric("评分", f"{scheme.score:.1f}/10")

    # 组件列表
    st.subheader("🧩 组件列表")
    for comp in scheme.architecture.components:
        with st.container():
            st.markdown(f"""
            <div class="component-card">
                <strong>{comp.name}</strong> ({comp.category})<br>
                安全级别: {comp.security.security_level}位
            </div>
            """, unsafe_allow_html=True)

    # 参数
    st.subheader("⚙️ 参数配置")
    param_col1, param_col2, param_col3 = st.columns(3)

    with param_col1:
        if scheme.parameters.key_size:
            st.metric("密钥长度", f"{scheme.parameters.key_size} 位")

    with param_col2:
        if scheme.parameters.nonce_size:
            st.metric("Nonce长度", f"{scheme.parameters.nonce_size} 位")

    with param_col3:
        if scheme.parameters.tag_size:
            st.metric("Tag长度", f"{scheme.parameters.tag_size} 位")

    # 安全属性
    st.subheader("🔒 安全属性")
    for prop in scheme.security_analysis.properties:
        st.success(f"✅ {prop}")

    if scheme.security_analysis.concerns:
        st.subheader("⚠️ 安全顾虑")
        for concern in scheme.security_analysis.concerns:
            st.warning(f"⚠️ {concern}")

    # 验证方案
    st.subheader("✔️ 方案验证")
    with st.spinner("⏳ 验证中..."):
        is_valid, errors, warnings = quick_validate(
            scheme_type=scheme.metadata.scheme_type,
            components=scheme.architecture.components,
            security_level=scheme.requirements.security.security_level,
            parameters={
                "key_size": scheme.parameters.key_size,
                "nonce_size": scheme.parameters.nonce_size,
                "tag_size": scheme.parameters.tag_size,
            }
        )

    if is_valid:
        st.markdown('<div class="success-box">✅ 方案验证通过</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="error-box">❌ 方案验证失败</div>', unsafe_allow_html=True)

    if errors:
        st.error(f"**错误 ({len(errors)}):**")
        for error in errors:
            st.write(f"- {error}")

    if warnings:
        st.warning(f"**警告 ({len(warnings)}):**")
        for warning in warnings:
            st.write(f"- {warning}")

    # 设计理由
    if scheme.design_rationale:
        with st.expander("💡 设计理由", expanded=False):
            st.write(scheme.design_rationale)

    # 代码生成
    if generate_code:
        render_code_generation(scheme)


def render_code_generation(scheme):
    """渲染代码生成结果"""
    st.subheader("💻 代码实现")

    with st.spinner("⏳ 生成代码中..."):
        codegen = CodeGenerator()
        implementation = codegen.generate_all(scheme)
        scheme.implementation = implementation

    # 使用tabs显示不同语言的代码
    code_tabs = st.tabs(["🐍 Python", "🔧 C", "📝 伪代码"])

    with code_tabs[0]:
        st.code(implementation.python, language="python")
        st.download_button(
            "⬇️ 下载Python代码",
            implementation.python,
            file_name=f"{scheme.metadata.name.replace(' ', '_')}.py",
            mime="text/x-python"
        )

    with code_tabs[1]:
        st.code(implementation.c, language="c")
        st.download_button(
            "⬇️ 下载C代码",
            implementation.c,
            file_name=f"{scheme.metadata.name.replace(' ', '_')}.c",
            mime="text/x-c"
        )

    with code_tabs[2]:
        st.code(implementation.pseudocode, language="text")


def main():
    """主函数"""
    init_session_state()
    render_header()
    render_sidebar()

    # 输入区域
    generate_btn, requirement_text, num_variants, generate_code = render_input_section()

    # 生成流程
    if generate_btn and requirement_text:
        st.session_state.current_requirement = requirement_text

        # 类型检测
        render_scheme_type_detection(requirement_text)

        # 需求解析
        render_requirement_parsing(requirement_text)

        # 方案生成
        if st.session_state.parsed_requirement:
            schemes = render_scheme_generation(
                st.session_state.parsed_requirement.requirement,
                num_variants
            )

            if schemes:
                # 显示方案
                render_scheme_display(schemes, generate_code)

    # 如果已经有生成的方案，直接显示
    elif st.session_state.generated_schemes:
        st.info("💡 下方显示的是上次生成的方案")
        render_scheme_display(
            st.session_state.generated_schemes,
            generate_code=True
        )

    # 页脚
    st.markdown("---")
    st.markdown(
        '<p style="text-align: center; color: #666;">'
        '⚠️ 本工具生成的方案仅供研究和原型设计使用，生产环境请咨询专业密码学专家'
        '</p>',
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()
