# agent-context-redactor

`agent-context-redactor` 是一个离线 Python CLI，用来在把仓库文件、日志、工单、`.env` 样例或数据库导出片段交给 Codex、Claude Code、Cursor 等 AI 编程代理之前，生成可分享的上下文包并按策略脱敏。

它的目标不是替代安全审计，也不是只做一次 `grep secret`。它会尽量保留目录结构和文本结构，把敏感值替换成可复查的占位符，同时生成 manifest、风险摘要、替换计数和安全 diff，方便团队在共享上下文前做最后确认。

## 特性

- Python 3.9+，运行时零第三方依赖。
- 可安装 CLI：`agent-context-redactor`。
- 子命令：`scan`、`pack`、`redact`、`check`、`init-policy`。
- 报告格式：Markdown、JSON 或 SARIF 2.1.0。
- 输出 ZIP 上下文包，自动创建 `--output` 父目录。
- 检测 secret-like assignment、URL credential、email、phone、person-like PII。
- 支持 custom regex、include/exclude paths、max file size、required review labels。
- 跳过大文件和二进制文件。
- 保留文件结构，生成替换审计计数、安全 diff、manifest hash。
- 适合 CI 中用 `--check warning|error` 控制是否失败。

## 安装

从项目根目录安装：

```bash
python -m pip install .
```

开发时也可以直接运行模块：

```bash
python -m agent_context_redactor --help
```

## 快速开始

生成策略文件：

```bash
agent-context-redactor init-policy --output redactor-policy.json
```

扫描当前目录并输出 Markdown 报告：

```bash
agent-context-redactor scan . --policy redactor-policy.json --format markdown --output reports/context-risk.md
```

生成脱敏目录：

```bash
agent-context-redactor redact . --policy redactor-policy.json --output out/redacted-context --check warning
```

生成 ZIP 上下文包：

```bash
agent-context-redactor pack . --policy redactor-policy.json --output out/context-pack.zip --check warning
```

CI 检查，发现问题时失败：

```bash
agent-context-redactor check . --policy redactor-policy.json --format json --output reports/context-risk.json --check error
```

输出 SARIF，上传到 GitHub Code Scanning：

```bash
agent-context-redactor scan . --policy redactor-policy.json --format sarif --output reports/context-risk.sarif
```

## 策略文件

策略文件是 JSON。默认策略由 `init-policy` 生成，结构如下：

```json
{
  "include_paths": ["**/*"],
  "exclude_paths": [".git/**", ".venv/**", "venv/**", "__pycache__/**", "dist/**", "build/**", "*.zip"],
  "max_file_size": 1048576,
  "classification_labels": {
    "credential": "Secrets, tokens, keys, passwords, and URL credentials",
    "pii": "Email, phone, and person-like personal data",
    "custom": "Project-defined sensitive pattern"
  },
  "required_review_labels": ["credential"],
  "redaction_patterns": []
}
```

自定义规则示例：

```json
{
  "redaction_patterns": [
    {
      "name": "internal_ticket",
      "regex": "\\b(?P<value>SEC-[0-9]{4,})\\b",
      "label": "custom",
      "replacement": "[REDACTED:ticket]",
      "description": "Internal security ticket id"
    }
  ]
}
```

内置规则和自定义规则都会运行。推荐把团队一定要人工复查的标签加入 `required_review_labels`，例如 `credential` 和 `custom`。

## 输出内容

`redact` 输出目录会包含：

- 原目录结构下的脱敏文件。
- `context_manifest.json`：文件 hash、manifest hash、跳过文件、替换计数。
- `redaction_report.json` 和 `redaction_report.md`：风险摘要和 finding 列表。
- `REVIEW_DIFF.md`：原始敏感值已被 hash 标记替代的安全 diff。

`pack` 会把同样内容写入 ZIP。

## CI

项目自带 GitHub Actions 配置，会在 Python 3.9 到 3.12 上运行：

```bash
python -m unittest discover -s tests
python -m agent_context_redactor --help
```

你可以在自己的流水线中使用：

```bash
agent-context-redactor check . --policy redactor-policy.json --check error --format json --output reports/context-risk.json
```

如果希望把上下文泄露风险显示在 GitHub Code Scanning 中，可以上传 SARIF：

```yaml
- run: agent-context-redactor scan . --policy redactor-policy.json --format sarif --output reports/context-risk.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/context-risk.sarif
```

## 隐私边界

- 本工具默认离线运行，不向网络发送内容。
- 报告中的 finding 不保存原始敏感值，只保存短 hash、位置、标签和替换后的 excerpt；SARIF 也遵守同样边界。
- `REVIEW_DIFF.md` 会先把原始敏感值替换为 hash 标记，再与脱敏结果做 diff。
- 它不能证明上下文“绝对安全”，只能降低常见泄露风险并让复查更系统。
- 压缩包仍可能包含未被规则覆盖的业务敏感信息，分享前仍需人工检查。

## 适用场景

- 把最小可复现仓库片段交给 AI 编程代理。
- 分享日志、工单、配置样例或 SQL/CSV 片段做调试。
- 在团队内建立“先脱敏再喂给 agent”的轻量流程。
- 在 CI 中阻止明显 credential 进入可分享上下文包。

## 限制

- 规则基于正则和启发式，可能误报或漏报。
- person-like PII 只识别常见赋值结构，不做人名数据库匹配。
- 二进制、大文件默认跳过，需要另行处理。
- 不解析压缩包、数据库专有格式或图片中的文字。
- 不替代 DLP、密钥轮换、合规审计或法律意见。

## English

`agent-context-redactor` is an offline Python CLI for creating redacted, reviewable context packages before sharing repository files, logs, tickets, environment samples, or data snippets with AI coding agents.

It preserves directory structure, replaces sensitive values with policy-driven placeholders, and emits JSON, Markdown, or SARIF 2.1.0 reports, a manifest with hashes, replacement counts, and a safe review diff. It is designed for local workflows and CI checks, with no runtime dependencies.

Basic usage:

```bash
agent-context-redactor init-policy
agent-context-redactor scan . --format json --output reports/context-risk.json
agent-context-redactor scan . --format sarif --output reports/context-risk.sarif
agent-context-redactor pack . --output out/context-pack.zip --check warning
agent-context-redactor check . --check error
```

SARIF output can be uploaded with `github/codeql-action/upload-sarif@v3` so context-sharing risks appear in GitHub Code Scanning. Reports include redacted excerpts and value hashes, not raw sensitive values.

Privacy note: the tool runs offline by default and avoids storing raw sensitive values in reports, but it cannot guarantee complete detection. Always review generated context packages before sharing them.
