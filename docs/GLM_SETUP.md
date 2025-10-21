# 使用智谱 GLM 模型指南

CipherGenius 现在支持使用智谱 AI 的 GLM 模型，这是 OpenAI 的一个优秀替代方案，特别适合国内用户使用。

## 为什么选择 GLM？

- ✅ **国内访问稳定**：无需科学上网，访问速度快
- ✅ **价格优惠**：相比 OpenAI 更具性价比
- ✅ **中文优化**：对中文任务有更好的理解能力
- ✅ **兼容性好**：API 接口与 OpenAI 类似，易于切换

## 快速开始

### 1. 获取 API Key

访问 [智谱AI开放平台](https://open.bigmodel.cn/) 注册并获取 API Key。

### 2. 安装依赖

```bash
pip install zhipuai
```

如果使用 Poetry：

```bash
poetry add zhipuai
```

### 3. 配置环境变量

编辑项目根目录的 `.env` 文件：

```env
# LLM Provider 配置
DEFAULT_LLM_PROVIDER=zhipuai
ZHIPUAI_API_KEY=your_api_key_here
ZHIPUAI_MODEL=glm-4
```

### 4. 运行测试

```bash
python test_glm.py
```

## 可用的 GLM 模型

| 模型名称 | 说明 | 推荐用途 |
|---------|------|---------|
| `glm-4` | 最新的 GLM-4 模型 | 通用任务，平衡性能和成本 |
| `glm-4-plus` | GLM-4 增强版 | 复杂推理任务 |
| `glm-3-turbo` | 更快速的版本 | 简单任务，追求速度 |

在 `.env` 文件中修改 `ZHIPUAI_MODEL` 来切换模型。

## Python 代码示例

### 基础使用

```python
from cipher_genius.core.llm_interface import get_llm_interface

# 获取 GLM 接口
llm = get_llm_interface("zhipuai")

# 文本生成
response = llm.generate(
    prompt="解释什么是 AES 加密算法",
    temperature=0.7,
    max_tokens=500
)
print(response)
```

### JSON 输出

```python
# 生成结构化 JSON
json_response = llm.generate_json(
    prompt="列出 3 种对称加密算法及其特点",
    temperature=0.5
)
print(json_response)
```

### 完整的密码方案生成

```python
from cipher_genius.core.parser import RequirementParser
from cipher_genius.core.generator import SchemeGenerator

# 解析需求
parser = RequirementParser()
parsed = parser.parse(
    "为物联网设备生成轻量级加密方案，需要 128 位安全性"
)

# 生成方案
generator = SchemeGenerator()
schemes = generator.generate(parsed.requirement, num_variants=2)

# 查看结果
for scheme in schemes:
    print(f"方案: {scheme.metadata.name}")
    print(f"评分: {scheme.score}/10")
    print(scheme.get_specification())
```

## 配置选项

在 `.env` 文件中可配置的 GLM 相关选项：

```env
# API 配置
ZHIPUAI_API_KEY=your_api_key_here

# 模型选择
ZHIPUAI_MODEL=glm-4  # glm-4, glm-4-plus, glm-3-turbo

# 设为默认提供者
DEFAULT_LLM_PROVIDER=zhipuai
```

## 在多个 LLM 之间切换

CipherGenius 支持在不同 LLM 提供者之间灵活切换：

```python
from cipher_genius.core.llm_interface import get_llm_interface

# 使用 GLM
llm_glm = get_llm_interface("zhipuai")

# 使用 OpenAI (如果配置了)
llm_openai = get_llm_interface("openai")

# 使用 Anthropic (如果配置了)
llm_anthropic = get_llm_interface("anthropic")

# 使用默认提供者（在 .env 中配置）
llm_default = get_llm_interface()
```

## 性能对比

基于我们的测试（非官方）：

| 指标 | GLM-4 | GPT-4 | Claude 3 |
|------|-------|-------|----------|
| 中文理解 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 代码生成 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 响应速度 | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| 价格 | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| 国内访问 | ⭐⭐⭐⭐⭐ | ⭐ | ⭐ |

## 常见问题

### Q: GLM 支持哪些功能？

A: GLM 支持 CipherGenius 的所有功能，包括：
- 需求解析
- 密码方案生成
- 代码生成（Python、C、Rust）
- JSON 结构化输出

### Q: 如何获得最佳性能？

A: 建议：
- 使用 `glm-4` 作为通用模型
- 对于复杂推理，使用 `glm-4-plus`
- 设置合适的 `temperature`（0.5-0.7 为佳）
- 控制 `max_tokens` 以优化成本

### Q: 遇到 API 错误怎么办？

A: 检查以下几点：
1. API Key 是否正确配置
2. 网络连接是否正常
3. API 额度是否充足
4. 查看智谱 AI 控制台的使用统计

### Q: 可以混合使用不同的 LLM 吗？

A: 可以！您可以在代码中为不同任务使用不同的 LLM：

```python
# 用 GLM 解析需求（中文友好）
parser_llm = get_llm_interface("zhipuai")

# 用 GPT-4 生成代码（代码质量高）
codegen_llm = get_llm_interface("openai")
```

## 支持与反馈

如有问题或建议，请：
- 提交 GitHub Issue
- 查看智谱 AI 官方文档：https://open.bigmodel.cn/dev/api
- 联系项目维护者

## 更新日志

- **2024-01**: 添加 GLM-4 支持
- **2024-01**: 优化中文 prompt 模板
- **2024-01**: 添加完整的测试覆盖

---

**提示**: 本文档持续更新中。如发现问题或有改进建议，欢迎贡献！
