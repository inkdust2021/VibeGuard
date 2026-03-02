# PII Next（原型）

本目录用于实现“更友好的隐私信息匹配（Presidio 风格内置规则）+ 关键词匹配”的**独立原型**。

约束（按仓库约定）：

- 仅新增文件，不改动现有逻辑；待你本地验证无误后再接入代理主流程。
- 不依赖外部 HTTP 服务，所有识别/替换逻辑在进程内完成。

## 覆盖范围（当前原型）

- 关键词：精确字符串匹配（优先级最高）
- Presidio 风格内置规则（纯 Go）：
  - `EMAIL`、`PHONE`、`URL`
  - `IP`（IPv4/IPv6）、`MAC`、`UUID`
  - `CREDIT_CARD`（Luhn 校验）、`IBAN`（mod-97 校验）、`SSN`
  - `CRYPTO`（BTC/ETH 地址格式）

## 重叠处理策略

多规则重叠时采用“高优先级优先”的贪心选择：直接丢弃低优先级命中，避免把大命中拆成碎片替换造成误替换。

快速自测：

```bash
go test ./internal/pii_next/...
```

手动跑一条示例（不显示原文）：

```bash
echo "hi I'm Samuel Porter. My email is Samuel@gmail.com." | go run ./internal/pii_next/demo --keyword "Samuel Porter"
```

## 体积预估（合并进 vibeguard 后）

- 仅引入本目录的纯 Go 识别器（regex + 校验逻辑）：对最终二进制体积的增量通常 **< 1MB**（实际取决于链接与裁剪）。
- 若后续加入 NLP/ONNX（PERSON/ORG/LOC/DATE 等实体识别）：需要额外的运行库与模型文件，镜像/发布包体积常见会增加 **几十到上百 MB**（取决于模型与分发方式）。
