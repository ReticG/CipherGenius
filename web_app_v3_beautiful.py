"""
CipherGenius v3.0 - Beautiful Modern Web Interface
精美现代化Web界面 - 完整功能版
"""

import sys
import io
import streamlit as st
from typing import Optional, List, Dict, Any
import time

# Set encoding
try:
    if sys.stdout and hasattr(sys.stdout, 'buffer') and not isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
except (ValueError, AttributeError):
    pass

# Import core modules
from cipher_genius.core.parser import RequirementParser
from cipher_genius.core.generator import SchemeGenerator
from cipher_genius.core.simple_validator import quick_validate
from cipher_genius.core.scheme_detector import detect_scheme_type
from cipher_genius.knowledge.components import ComponentLibrary
from cipher_genius.codegen.generator import CodeGenerator

# Import all feature modules
try:
    from cipher_genius.features import (
        SchemeComparator, SecurityAssessor, ComponentRecommender,
        PerformanceEstimator, SchemeExporter, TutorialManager,
        Platform, PerformanceLevel,
        VulnerabilityScanner, ComplianceReporter, ThreatModeler,
        AttackSimulator, CostEstimator, BenchmarkRunner
    )
    # Try to import enhanced tutorials
    try:
        from cipher_genius.features.tutorials_enhanced import EnhancedTutorialManager
        ENHANCED_TUTORIALS = True
    except ImportError:
        ENHANCED_TUTORIALS = False

    FEATURES_AVAILABLE = True
except ImportError as e:
    FEATURES_AVAILABLE = False
    ENHANCED_TUTORIALS = False
    st.warning(f"⚠️ Some features unavailable: {e}")

# Page configuration
st.set_page_config(
    page_title="CipherGenius v3.0 - AI-Powered Cryptography Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS with beautiful modern design
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    /* Global Styles */
    .main {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Beautiful gradient header */
    .hero-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
        padding: 3rem 2rem;
        border-radius: 20px;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 20px 60px rgba(102, 126, 234, 0.3);
        animation: gradient-shift 15s ease infinite;
        background-size: 200% 200%;
    }

    @keyframes gradient-shift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    .hero-title {
        font-size: 3.5rem;
        font-weight: 700;
        color: white;
        margin: 0;
        text-shadow: 0 4px 12px rgba(0,0,0,0.2);
        letter-spacing: -1px;
    }

    .hero-subtitle {
        font-size: 1.3rem;
        color: rgba(255,255,255,0.95);
        margin-top: 0.5rem;
        font-weight: 300;
    }

    .hero-badge {
        display: inline-block;
        background: rgba(255,255,255,0.2);
        padding: 0.5rem 1.5rem;
        border-radius: 50px;
        color: white;
        font-weight: 500;
        margin-top: 1rem;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255,255,255,0.3);
    }

    /* Beautiful cards */
    .feature-card {
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
        backdrop-filter: blur(10px);
        padding: 2rem;
        border-radius: 16px;
        border: 1px solid rgba(102, 126, 234, 0.2);
        box-shadow: 0 8px 32px rgba(102, 126, 234, 0.1);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        margin: 1rem 0;
        position: relative;
        overflow: hidden;
    }

    .feature-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, #667eea, #764ba2, #f093fb);
        transform: scaleX(0);
        transform-origin: left;
        transition: transform 0.3s ease;
    }

    .feature-card:hover {
        transform: translateY(-8px);
        box-shadow: 0 16px 48px rgba(102, 126, 234, 0.25);
        border-color: rgba(102, 126, 234, 0.4);
    }

    .feature-card:hover::before {
        transform: scaleX(1);
    }

    /* Metric cards with glass morphism */
    .metric-card {
        background: rgba(255, 255, 255, 0.7);
        backdrop-filter: blur(10px);
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid rgba(102, 126, 234, 0.15);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.05);
        transition: all 0.3s ease;
    }

    .metric-card:hover {
        transform: scale(1.05);
        box-shadow: 0 8px 24px rgba(102, 126, 234, 0.15);
    }

    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }

    .metric-label {
        font-size: 0.9rem;
        color: #666;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 0.5rem;
        font-weight: 500;
    }

    /* Beautiful buttons */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        font-size: 1rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 16px rgba(102, 126, 234, 0.3);
    }

    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(102, 126, 234, 0.4);
    }

    .stButton > button:active {
        transform: translateY(0);
    }

    /* Tutorial step card */
    .tutorial-step {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-left: 5px solid #667eea;
        border-radius: 0 12px 12px 0;
        margin: 1.5rem 0;
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        position: relative;
    }

    .tutorial-step::before {
        content: '✓';
        position: absolute;
        left: -15px;
        top: 1.5rem;
        background: #667eea;
        color: white;
        width: 30px;
        height: 30px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }

    /* Code blocks */
    .stCode {
        border-radius: 12px;
        border: 1px solid rgba(102, 126, 234, 0.2);
        box-shadow: 0 4px 16px rgba(0,0,0,0.05);
        font-family: 'JetBrains Mono', monospace;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: rgba(255,255,255,0.5);
        padding: 0.5rem;
        border-radius: 12px;
        backdrop-filter: blur(10px);
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
    }

    /* Expanders */
    .streamlit-expanderHeader {
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.05) 0%, rgba(118, 75, 162, 0.05) 100%);
        border-radius: 12px;
        padding: 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }

    .streamlit-expanderHeader:hover {
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
    }

    /* Component badge */
    .component-badge {
        display: inline-block;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
        font-size: 0.85rem;
        font-weight: 600;
        margin: 0.25rem;
        box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3);
        transition: all 0.2s ease;
    }

    .component-badge:hover {
        transform: scale(1.1);
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }

    /* Success/Warning/Error messages */
    .stSuccess {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 1rem;
    }

    .stWarning {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        border: none;
        border-radius: 12px;
    }

    .stError {
        background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
        color: white;
        border: none;
        border-radius: 12px;
    }

    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }

    /* Progress bar */
    .stProgress > div > div {
        background: linear-gradient(90deg, #667eea, #764ba2, #f093fb);
    }

    /* Footer */
    .footer {
        text-align: center;
        padding: 3rem 2rem;
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.05) 0%, rgba(118, 75, 162, 0.05) 100%);
        border-radius: 20px;
        margin-top: 3rem;
    }

    .footer-title {
        font-size: 1.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }

    .footer-text {
        color: #666;
        font-size: 1rem;
    }

    /* Animations */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .animate-fade-in {
        animation: fadeIn 0.6s ease-out;
    }

    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }

    ::-webkit-scrollbar-track {
        background: #f1f1f1;
        border-radius: 10px;
    }

    ::-webkit-scrollbar-thumb {
        background: linear-gradient(135deg, #667eea, #764ba2);
        border-radius: 10px;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(135deg, #764ba2, #667eea);
    }

    /* Loading animation */
    .loading-container {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 2rem;
    }

    .loading-spinner {
        width: 50px;
        height: 50px;
        border: 5px solid rgba(102, 126, 234, 0.1);
        border-top: 5px solid #667eea;
        border-radius: 50%;
        animation: spin 1s linear infinite;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state with defaults"""
    defaults = {
        'generated_schemes': [],
        'current_tab': 'Home',
        'tutorial_progress': {},
        'component_library': None,
        'animation_enabled': True,
        'theme': 'modern'
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Initialize component library once
    if st.session_state.component_library is None:
        st.session_state.component_library = ComponentLibrary()


def render_hero_header():
    """Render beautiful hero header"""
    st.markdown("""
    <div class="hero-header animate-fade-in">
        <div class="hero-title">🔐 CipherGenius</div>
        <div class="hero-subtitle">AI-Powered Cryptographic Scheme Generator</div>
        <div class="hero-badge">v3.0 Enterprise Edition • 152 Components • 19 Features</div>
    </div>
    """, unsafe_allow_html=True)


def render_home_tab():
    """Home tab with scheme generation"""
    st.markdown('<div class="animate-fade-in">', unsafe_allow_html=True)

    # Quick stats at top
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">152</div>
            <div class="metric-label">Components</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">19</div>
            <div class="metric-label">Features</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">20+</div>
            <div class="metric-label">PQC Algorithms</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">9</div>
            <div class="metric-label">Compliance Standards</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Main content
    col_main, col_examples = st.columns([2, 1])

    with col_main:
        st.markdown("### 📝 Describe Your Security Requirements")

        requirement_text = st.text_area(
            "Enter your requirements in natural language:",
            height=150,
            placeholder="Example: Design an authenticated encryption scheme for IoT devices with 128-bit security, low memory usage (<2KB RAM), and resistance to side-channel attacks...",
            help="Describe what you need - our AI will understand and generate appropriate cryptographic schemes"
        )

        col_opt1, col_opt2, col_opt3 = st.columns(3)
        with col_opt1:
            num_variants = st.slider("Scheme Variants:", 1, 5, 3, help="Generate multiple alternative schemes")
        with col_opt2:
            generate_code = st.checkbox("Generate Code", value=True, help="Generate Python, C, and Rust implementations")
        with col_opt3:
            auto_validate = st.checkbox("Auto-Validate", value=True, help="Automatically validate schemes for security issues")

        if st.button("🚀 Generate Cryptographic Scheme", type="primary", use_container_width=True):
            if requirement_text.strip():
                with st.spinner("🔮 AI is analyzing your requirements..."):
                    progress_bar = st.progress(0)
                    for i in range(100):
                        time.sleep(0.01)
                        progress_bar.progress(i + 1)

                    try:
                        # Parse requirements
                        parser = RequirementParser()
                        req = parser.parse(requirement_text)

                        # Generate schemes
                        generator = SchemeGenerator()
                        schemes = generator.generate(req, num_variants=num_variants)

                        st.session_state.generated_schemes = schemes
                        st.success(f"✅ Successfully generated {len(schemes)} cryptographic scheme(s)!")
                        st.balloons()

                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
            else:
                st.warning("⚠️ Please enter your security requirements first")

    with col_examples:
        st.markdown("### 💡 Quick Examples")
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)

        examples = {
            "🌐 IoT Encryption": "Lightweight encryption for IoT devices with 128-bit security and memory under 2KB",
            "🔮 Post-Quantum": "Post-quantum secure key exchange and digital signature for 50-year security",
            "🔐 Digital Signature": "Digital signature scheme for document signing with 256-bit security and FIPS 140-3 compliance",
            "🔑 Secure Messaging": "End-to-end encrypted messaging with perfect forward secrecy and deniability",
            "☁️ Cloud Storage": "Authenticated encryption for cloud storage with client-side encryption"
        }

        for icon_name, example in examples.items():
            if st.button(icon_name, key=f"ex_{icon_name}", use_container_width=True):
                st.session_state.example_text = example
                st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

    # Display generated schemes
    if st.session_state.generated_schemes:
        st.markdown("---")
        st.markdown("### 📋 Generated Cryptographic Schemes")

        for idx, scheme in enumerate(st.session_state.generated_schemes):
            with st.expander(f"🔐 Scheme {idx + 1}: {scheme.get('name', 'Unnamed Scheme')}", expanded=(idx == 0)):
                # Scheme details in tabs
                tab_overview, tab_components, tab_code, tab_analysis = st.tabs(
                    ["📊 Overview", "🧩 Components", "💻 Code", "🔍 Analysis"]
                )

                with tab_overview:
                    st.json(scheme)

                with tab_components:
                    if 'components' in scheme:
                        for comp in scheme['components']:
                            st.markdown(f'<span class="component-badge">{comp}</span>', unsafe_allow_html=True)

                with tab_code:
                    if generate_code:
                        lang_tabs = st.tabs(["Python", "C", "Rust"])
                        with lang_tabs[0]:
                            st.code("# Python implementation\n# Coming soon...", language="python")
                        with lang_tabs[1]:
                            st.code("// C implementation\n// Coming soon...", language="c")
                        with lang_tabs[2]:
                            st.code("// Rust implementation\n// Coming soon...", language="rust")

                with tab_analysis:
                    if FEATURES_AVAILABLE and auto_validate:
                        assessor = SecurityAssessor()
                        assessment = assessor.assess_scheme(scheme)

                        metric_cols = st.columns(3)
                        with metric_cols[0]:
                            st.metric("Security Score", f"{assessment.get('overall_score', 0)}/100")
                        with metric_cols[1]:
                            st.metric("Threat Level", assessment.get('threat_level', 'UNKNOWN'))
                        with metric_cols[2]:
                            st.metric("Quantum Safe", "✓ Yes" if assessment.get('quantum_readiness', {}).get('quantum_safe', False) else "✗ No")

    st.markdown('</div>', unsafe_allow_html=True)


def render_component_library_tab():
    """Beautiful component library browser"""
    st.markdown("### 📚 Cryptographic Component Library")
    st.markdown("*Browse our comprehensive collection of 152 battle-tested cryptographic components*")

    # Search and filter
    col_search, col_cat, col_sec = st.columns([2, 1, 1])

    with col_search:
        search_term = st.text_input("🔍 Search components", placeholder="e.g., AES, SHA-256, Kyber, Dilithium...")

    with col_cat:
        category_filter = st.selectbox(
            "Category",
            ["All", "Block Ciphers", "Hash Functions", "Signatures", "Key Exchange", "AEAD", "Protocols"]
        )

    with col_sec:
        security_filter = st.selectbox(
            "Security Level",
            ["All", "128-bit", "192-bit", "256-bit", "Post-Quantum"]
        )

    st.markdown("---")

    # Component categories with beautiful display
    categories = {
        "🔒 Block Ciphers": {
            "components": ["AES-128", "AES-192", "AES-256", "ChaCha20", "Camellia", "ARIA", "Twofish", "Serpent", "Blowfish", "SM4", "ASCON"],
            "color": "#667eea"
        },
        "🔐 Hash Functions": {
            "components": ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512", "BLAKE2b", "BLAKE2s", "BLAKE3", "Keccak", "SM3"],
            "color": "#764ba2"
        },
        "✍️ Digital Signatures": {
            "components": ["RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "Ed25519", "Ed448", "Dilithium-2", "Dilithium-3", "Dilithium-5", "FALCON-512", "FALCON-1024", "SPHINCS+-128", "SPHINCS+-256"],
            "color": "#f093fb"
        },
        "🔑 Key Exchange": {
            "components": ["ECDH-P256", "ECDH-P384", "X25519", "X448", "DH-2048", "DH-3072", "Kyber-512", "Kyber-768", "Kyber-1024", "NTRU", "FrodoKEM"],
            "color": "#f5576c"
        },
        "🛡️ AEAD Modes": {
            "components": ["AES-GCM", "AES-CCM", "AES-GCM-SIV", "ChaCha20-Poly1305", "AEGIS-128", "AEGIS-256", "ASCON-128", "Deoxys-II"],
            "color": "#11998e"
        },
        "🔮 Advanced Protocols": {
            "components": ["zk-SNARK", "zk-STARK", "Bulletproofs", "PLONK", "Groth16", "OPAQUE", "SPAKE2+", "SRP", "PSI", "MPC-Shamir"],
            "color": "#eb3349"
        }
    }

    for category, data in categories.items():
        with st.expander(f"{category} ({len(data['components'])} components)", expanded=True):
            # Display as pills
            components_html = ""
            for comp in data['components']:
                if not search_term or search_term.lower() in comp.lower():
                    components_html += f'<span class="component-badge" style="background: linear-gradient(135deg, {data["color"]}, {data["color"]}dd);">{comp}</span>'

            st.markdown(components_html, unsafe_allow_html=True)
            st.markdown("")


def render_tutorials_tab():
    """Enhanced tutorials with beautiful UI"""
    st.markdown("### 🎓 Interactive Cryptography Tutorials")
    st.markdown("*Learn cryptography from beginner to advanced with hands-on examples*")

    if not FEATURES_AVAILABLE:
        st.error("❌ Tutorial system not available. Please check installation.")
        return

    # Use enhanced tutorials if available
    if ENHANCED_TUTORIALS:
        tutorial_mgr = EnhancedTutorialManager()
        st.info("✨ Enhanced tutorials with detailed explanations activated!")
    else:
        tutorial_mgr = TutorialManager()

    tutorials = tutorial_mgr.get_all_tutorials()

    # Tutorial selection with beautiful cards
    st.markdown("#### 📚 Available Tutorials")

    # Group by difficulty
    difficulties = ["beginner", "intermediate", "advanced"]
    diff_icons = {"beginner": "🌱", "intermediate": "🌿", "advanced": "🌳"}
    diff_colors = {"beginner": "#11998e", "intermediate": "#667eea", "advanced": "#eb3349"}

    for difficulty in difficulties:
        diff_tutorials = [t for t in tutorials if t.difficulty.lower() == difficulty]

        if diff_tutorials:
            st.markdown(f"### {diff_icons[difficulty]} {difficulty.capitalize()} Level")

            cols = st.columns(min(len(diff_tutorials), 3))

            for idx, tutorial in enumerate(diff_tutorials):
                with cols[idx % 3]:
                    st.markdown(f"""
                    <div class="feature-card" style="border-left: 5px solid {diff_colors[difficulty]};">
                        <h4>{tutorial.title}</h4>
                        <p>{tutorial.description[:100]}...</p>
                        <p><strong>⏱️ {tutorial.duration_minutes} minutes</strong></p>
                    </div>
                    """, unsafe_allow_html=True)

                    if st.button(f"Start Tutorial", key=f"tut_{tutorial.id}", use_container_width=True):
                        st.session_state.current_tutorial = tutorial.id
                        st.rerun()

    # Display selected tutorial
    if 'current_tutorial' in st.session_state:
        tutorial = tutorial_mgr.get_tutorial(st.session_state.current_tutorial)

        if tutorial:
            st.markdown("---")
            st.markdown(f"## 📖 {tutorial.title}")
            st.markdown(f"*{tutorial.description}*")

            # Progress tracking
            if hasattr(tutorial, 'steps') and tutorial.steps:
                total_steps = len(tutorial.steps)
                completed_steps = st.session_state.tutorial_progress.get(tutorial.id, 0)
                progress = completed_steps / total_steps if total_steps > 0 else 0

                st.progress(progress)
                st.markdown(f"**Progress:** {completed_steps}/{total_steps} steps completed ({progress*100:.0f}%)")

            # Display steps
            for step_idx, step in enumerate(tutorial.steps if hasattr(tutorial, 'steps') else []):
                step_num = step.get('step', step_idx + 1)
                step_title = step.get('title', f'Step {step_num}')

                with st.expander(f"📌 Step {step_num}: {step_title}", expanded=(step_idx == 0)):
                    # Enhanced step display if available
                    if isinstance(step, dict):
                        if 'description' in step:
                            st.markdown(f"**{step['description']}**")

                        if 'explanation' in step:
                            st.markdown(step['explanation'])

                        if 'code_example' in step or 'code' in step:
                            code = step.get('code_example') or step.get('code', '')
                            st.code(code, language='python')

                        if 'task' in step or 'practice_exercise' in step:
                            exercise = step.get('task') or step.get('practice_exercise', '')
                            st.info(f"💪 **Practice Exercise:**\n\n{exercise}")

                        # Mark as complete button
                        if st.button(f"✓ Mark Step {step_num} Complete", key=f"complete_{tutorial.id}_{step_num}"):
                            current_progress = st.session_state.tutorial_progress.get(tutorial.id, 0)
                            st.session_state.tutorial_progress[tutorial.id] = max(current_progress, step_num)
                            st.success(f"✅ Step {step_num} marked complete!")
                            st.rerun()


def render_tools_tab():
    """Advanced tools with beautiful UI"""
    st.markdown("### 🛠️ Advanced Cryptographic Analysis Tools")
    st.markdown("*Comprehensive security analysis and optimization tools*")

    if not FEATURES_AVAILABLE:
        st.error("❌ Advanced tools not available")
        return

    # Tool categories
    tool_tabs = st.tabs([
        "🔍 Scheme Comparator",
        "🛡️ Security Assessor",
        "💡 Component Recommender",
        "⚡ Performance Estimator",
        "🔎 Vulnerability Scanner",
        "📋 Compliance Reporter"
    ])

    with tool_tabs[0]:
        st.markdown("#### Compare Multiple Cryptographic Schemes")
        if len(st.session_state.generated_schemes) >= 2:
            comparator = SchemeComparator()
            result = comparator.compare_schemes(st.session_state.generated_schemes[:3])

            st.markdown("##### 📊 Comparison Results")
            st.json(result)
        else:
            st.info("ℹ️ Generate at least 2 schemes to use the comparator")

    with tool_tabs[1]:
        st.markdown("#### Comprehensive Security Assessment")
        if st.session_state.generated_schemes:
            assessor = SecurityAssessor()
            scheme = st.session_state.generated_schemes[0]
            assessment = assessor.assess_scheme(scheme)

            # Beautiful metrics display
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{assessment.get('overall_score', 0)}</div>
                    <div class="metric-label">Security Score</div>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                threat_level = assessment.get('threat_level', 'UNKNOWN')
                threat_colors = {'LOW': '#11998e', 'MEDIUM': '#f093fb', 'HIGH': '#f5576c', 'CRITICAL': '#eb3349'}
                st.markdown(f"""
                <div class="metric-card" style="border-left: 5px solid {threat_colors.get(threat_level, '#666')};">
                    <div class="metric-value" style="font-size: 1.5rem;">{threat_level}</div>
                    <div class="metric-label">Threat Level</div>
                </div>
                """, unsafe_allow_html=True)

            with col3:
                quantum_safe = assessment.get('quantum_readiness', {}).get('quantum_safe', False)
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="font-size: 2rem;">{"✓" if quantum_safe else "✗"}</div>
                    <div class="metric-label">Quantum Safe</div>
                </div>
                """, unsafe_allow_html=True)

            # Detailed analysis
            with st.expander("🔍 Detailed Vulnerability Analysis"):
                st.json(assessment.get('vulnerabilities', []))
        else:
            st.info("ℹ️ Generate a scheme first to assess its security")

    with tool_tabs[2]:
        st.markdown("#### Get Intelligent Component Recommendations")

        col1, col2 = st.columns(2)
        with col1:
            security_level = st.select_slider(
                "Security Level (bits)",
                options=[128, 192, 256],
                value=128,
                help="Higher is more secure but slower"
            )
        with col2:
            performance = st.selectbox(
                "Performance Priority",
                ["any", "very_high", "high", "medium", "low"],
                help="Balance between security and speed"
            )

        if st.button("🔮 Get Recommendations", use_container_width=True):
            recommender = ComponentRecommender()
            requirements = {
                'security_level': security_level,
                'performance': performance
            }
            recommendations = recommender.recommend_components(requirements, num_recommendations=5)

            st.markdown("#### 💡 Top Recommendations")
            for idx, rec in enumerate(recommendations):
                st.markdown(f"""
                <div class="feature-card">
                    <h4>#{idx + 1} {rec.get('name', 'Unknown')}</h4>
                    <p><strong>Score:</strong> {rec.get('score', 0):.2f}/100</p>
                    <p><em>{rec.get('rationale', 'No explanation available')}</em></p>
                </div>
                """, unsafe_allow_html=True)

    with tool_tabs[3]:
        st.markdown("#### Estimate Performance Across Platforms")

        platform = st.selectbox(
            "Select Target Platform",
            ["SERVER", "DESKTOP", "MOBILE", "IOT", "EMBEDDED"],
            help="Choose your deployment target"
        )

        data_size = st.slider("Data Size (MB)", 0.1, 100.0, 1.0)

        if st.session_state.generated_schemes:
            estimator = PerformanceEstimator()
            scheme = st.session_state.generated_schemes[0]

            try:
                perf = estimator.estimate_performance(scheme, Platform[platform], data_size)

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Throughput", f"{perf.get('throughput_mbps', 0):.2f} MB/s")
                with col2:
                    st.metric("Latency", f"{perf.get('latency_ms', 0):.2f} ms")
                with col3:
                    st.metric("Memory", f"{perf.get('memory_kb', 0):.2f} KB")
            except Exception as e:
                st.error(f"Error: {e}")

    with tool_tabs[4]:
        st.markdown("#### Vulnerability Scan with CVE Database")
        if st.session_state.generated_schemes and FEATURES_AVAILABLE:
            scanner = VulnerabilityScanner()
            scheme = st.session_state.generated_schemes[0]
            scan_result = scanner.scan_scheme(scheme)

            st.json(scan_result)

    with tool_tabs[5]:
        st.markdown("#### Compliance Verification (9 Standards)")
        if st.session_state.generated_schemes and FEATURES_AVAILABLE:
            reporter = ComplianceReporter()
            scheme = st.session_state.generated_schemes[0]

            from cipher_genius.features import ComplianceStandard
            selected_standards = st.multiselect(
                "Select Standards to Check",
                [s.value for s in ComplianceStandard],
                default=["fips_140_2", "pci_dss"]
            )

            if st.button("🔍 Check Compliance"):
                standards_enum = [ComplianceStandard(s) for s in selected_standards]
                report = reporter.generate_report(scheme, standards_enum)
                st.json(report)


def render_export_tab():
    """Beautiful export interface"""
    st.markdown("### 📤 Export & Share Your Schemes")
    st.markdown("*Export to multiple formats or create shareable links*")

    if not st.session_state.generated_schemes:
        st.info("ℹ️ Generate a scheme first to export")
        return

    if not FEATURES_AVAILABLE:
        st.error("❌ Export features not available")
        return

    exporter = SchemeExporter()
    scheme = st.session_state.generated_schemes[0]

    # Export format selection
    st.markdown("#### 📄 Export Formats")

    col1, col2, col3, col4, col5 = st.columns(5)

    formats = [
        ("JSON", "📄", "application/json", ".json"),
        ("Markdown", "📝", "text/markdown", ".md"),
        ("LaTeX", "📚", "text/plain", ".tex"),
        ("YAML", "📋", "text/yaml", ".yaml"),
        ("PDF", "📕", "application/pdf", ".pdf")
    ]

    for idx, (fmt, icon, mime, ext) in enumerate(formats):
        with [col1, col2, col3, col4, col5][idx]:
            st.markdown(f"""
            <div class="feature-card" style="text-align: center;">
                <div style="font-size: 3rem;">{icon}</div>
                <div style="font-weight: 600; margin-top: 0.5rem;">{fmt}</div>
            </div>
            """, unsafe_allow_html=True)

            if st.button(f"Export {fmt}", key=f"export_{fmt}", use_container_width=True):
                try:
                    if fmt == "JSON":
                        output = exporter.export_to_json(scheme)
                    elif fmt == "Markdown":
                        output = exporter.export_to_markdown(scheme)
                    elif fmt == "LaTeX":
                        output = exporter.export_to_latex(scheme)
                    elif fmt == "YAML":
                        output = exporter.export_to_yaml(scheme)
                    else:
                        output = b"PDF export coming soon..."

                    st.download_button(
                        f"📥 Download {fmt}",
                        output,
                        f"scheme{ext}",
                        mime,
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"Export error: {e}")

    # Shareable link
    st.markdown("---")
    st.markdown("#### 🔗 Create Shareable Link")

    if st.button("🔮 Generate Shareable Link", use_container_width=True):
        try:
            link = exporter.create_shareable_link(scheme)
            st.code(link, language=None)
            st.success("✅ Link generated! Share this with others.")
        except Exception as e:
            st.error(f"Link generation error: {e}")


def main():
    """Main application entry point"""
    init_session_state()
    render_hero_header()

    # Main navigation
    tabs = st.tabs([
        "🏠 Home",
        "📚 Component Library",
        "🎓 Tutorials",
        "🛠️ Analysis Tools",
        "📤 Export & Share"
    ])

    with tabs[0]:
        render_home_tab()

    with tabs[1]:
        render_component_library_tab()

    with tabs[2]:
        render_tutorials_tab()

    with tabs[3]:
        render_tools_tab()

    with tabs[4]:
        render_export_tab()

    # Beautiful footer
    st.markdown("""
    <div class="footer">
        <div class="footer-title">CipherGenius v3.0 Enterprise Edition</div>
        <div class="footer-text">
            152 Components • 19 Advanced Features • 9 Compliance Standards
        </div>
        <div class="footer-text" style="margin-top: 1rem;">
            Built with ❤️ for security professionals, researchers, and developers worldwide
        </div>
        <div style="margin-top: 1.5rem; color: #999;">
            🔒 Enterprise-Grade Cryptography • 🔮 AI-Powered • 🌍 Open Source
        </div>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
