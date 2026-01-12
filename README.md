
# HybriLink：融合对称密码与公钥密码的信息传输系统

> 这是一个简单的“公钥握手 + 对称AEAD数据通道 + 链式密钥演进（ratchet）”的端到端加密传输。
> 项目极度不成熟，请勿用于生产环境，请采用成熟协议栈（TLS 1.3、Noise、Signal 等）。

## 特性
- X25519 进行临时密钥协商（前向安全的基础）
- Ed25519 对握手关键字段签名（服务器认证/防中间人）
- HKDF 进行会话密钥派生（绑定握手 transcript）
- AES-256-GCM 进行数据加密与认证（AEAD）
- 简化的对称链式密钥演进：每条消息使用独立 message key（对历史消息提供“后向安全/前向保密”）

## Let's Start
### 1) 安装
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) 生成服务器身份密钥（Ed25519）
```bash
python -m hybrilink.gen_keys --outdir keys
```

### 3) 启动服务器
```bash
python -m hybrilink.server --host 127.0.0.1 --port 9000 --server-ed25519 keys/server_ed25519.pem
```

### 4) 启动客户端并发送消息
```bash
python -m hybrilink.client --host 127.0.0.1 --port 9000 --server-ed25519-pub keys/server_ed25519_pub.pem --message "hello"
```

## 协议摘要
- ClientHello: 版本、套件、client nonce、client 临时 X25519 公钥
- ServerHello: server nonce、server 临时 X25519 公钥、Ed25519 签名（覆盖双方 hello 字段）
- 会话密钥: HKDF( X25519(shared) || nonces, salt=SHA256(transcript) )
- 数据记录层: length-prefixed frame；record header 进入 AEAD 的 AAD；nonce= session_prefix + counter

## 目录结构
- `paper/`：Paper（md、docx、pdf）
- `src/hybrilink/`：核心SRC
- `tests/`：基础测试
