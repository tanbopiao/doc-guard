# Doc Guard · 工程资料保卫战引擎

面向工程资料与文档的智能审查引擎：对上传文档做合规检查与风险探测，输出可核验的自测证据。曾用于「创青春」参赛作品「工程资料保卫战」。

## 目录结构

```
doc_guard/
├── agent_docs.py        # 审查智能体
├── policy_docs.py       # 审查策略
├── run_selftest_docs.py # 自测入口
└── results/             # 自测与闸门探测证据（JSON）
```

## 快速开始

```bash
python run_selftest_docs.py
```

依赖：Python 3.10+。

## 设计要点

- 策略与智能体分离，审查规则可配置；
- 每次自测与探测结果落 `results/` 留证，可复核、可重放。

## 协议

代码以 MIT 协议开源。
