# TOTP Authenticator

一个本地优先的 TOTP 认证器，使用 Electron + SQLite 实现。  
当前版本为纯桌面架构，不再依赖本地 HTTP 服务。

## 当前功能

- 展示 TOTP 动态口令，按周期自动刷新
- 左侧环形倒计时显示剩余秒数
- 点击条目大部分区域直接复制验证码
- 条目内支持安全网址跳转
- 新增、编辑、删除条目
- 支持粘贴 `otpauth://totp/...` 或 Base32 Key 解析
- 编辑时密钥相关字段只读
- 新增时按密钥去重，禁止重复新增
- JSON 备份导出与恢复
- SQLite 本地持久化存储
- 条目网址仅允许 `http://` 或 `https://`

## 运行方式

```bash
npm install
npm start
```

## Windows 打包

先生成图标：

```bash
npm run generate:icon
```

再打包：

```bash
npm run dist:win
```

输出目录：

```text
dist/
```

当前仅生成：

- Windows `portable` 便携版 `.exe`

## 数据存储位置

SQLite 保存在 Electron 用户数据目录，例如 Windows 下通常类似：

```text
%APPDATA%/TOTP Authenticator/
```

## 交互说明

- 点击条目：
  复制当前验证码
- 点击网址图标：
  打开条目关联网址
- 点击右侧三点：
  编辑或删除条目
- 点击右下角 `+`：
  新增条目

## 安全说明

- 当前版本不会对 SQLite 中的密钥做额外加密
- JSON 备份中包含明文 TOTP 密钥
- 请妥善保护数据库文件、备份文件和打包产物

## 测试

```bash
npm test
```

## 项目结构

```text
electron/      Electron 主进程与 preload
src/           前端逻辑、IPC 存储接入与 TOTP 处理
test/          自动化测试
build/         打包图标资源
db.js          SQLite 存储层
index.html     主页面
styles.css     页面样式
```

## 备份格式

```json
{
  "version": 1,
  "updatedAt": 1711948800000,
  "entries": [
    {
      "id": "github-1711948800000",
      "label": "GitHub",
      "account": "work@example.com",
      "issuer": "GitHub",
      "secret": "JBSWY3DPEHPK3PXP",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "notes": "恢复码已保存在保险箱",
      "website": "https://github.com/settings/security",
      "createdAt": 1711948800000,
      "updatedAt": 1711948800000
    }
  ]
}
```
