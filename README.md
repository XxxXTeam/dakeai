# DakeAI 自动注册工具

自动完成 DakeAI CODEX 平台的注册流程并获取 API Key。

## 功能

- 使用临时邮箱自动注册
- 自动接收并提取验证码
- 自动创建 API Key 并保存到文件
- 支持多线程并发
- 彩色终端输出
- Debug 调试模式

## 安装

```bash
go install github.com/XxxXTeam/dakeai@latest
```

或手动编译：

```bash
git clone https://github.com/XxxXTeam/dakeai.git
cd dakeai
go build -o dakeai .
```

## 使用

```bash
# 默认单线程获取 1 个 Key
./dakeai

# 3 线程并发获取 5 个 Key
./dakeai -threads 3 -count 5

# 调试模式，输出每步详细信息
./dakeai -debug

# 组合使用
./dakeai -threads 3 -count 10 -debug
```

## 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-threads` | 1 | 并发线程数 |
| `-count` | 1 | 目标获取 Key 数量 |
| `-debug` | false | 调试模式 |

## 输出

获取到的 API Key 会自动保存到 `api_keys.txt`，格式：

```
时间 | 邮箱 | API Key
```

## 依赖

- [tempmail-sdk](https://github.com/XxxXTeam/tempmail-sdk) - 临时邮箱 SDK

## 许可证

[AGPL-3.0](LICENSE)
