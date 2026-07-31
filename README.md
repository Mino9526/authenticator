# TOTP Authenticator

一个本地优先的 TOTP 认证器，使用 Tauri 2 + SQLite 实现。  
发布版为纯桌面应用，不依赖本地 HTTP 服务；开发模式会通过 Vite dev server 提供页面。

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
npm start
```

说明：

- `npm start` 会以标准 Tauri 2 开发模式启动：`tauri dev + Vite`
- 开发模式下窗口访问的是 `http://localhost:1420`
- 发布版会把前端静态资源打进应用内，不会访问 `localhost:1420`
- 前端仍然是当前这套原生 HTML / CSS / JS 页面，只是构建方式切到了 Vite

常用命令：

```bash
npm run dev
npm run build
npm start
```

## Windows x64 便携版构建

前置条件：

- 可以在 Windows 终端直接执行
- 也可以在已配置 `cargo-xwin`、LLVM 和 Windows SDK 的 WSL/Linux 环境中交叉构建
- 已安装 Rust toolchain
- 如果是 Windows 原生构建，需要已安装 Windows C++ Build Tools / MSVC
- 已安装 x64 Windows 目标：

```bash
rustup target add x86_64-pc-windows-msvc
```

构建 Windows x64 便携版：

```bash
npm run dist:win
```

如果是在 WSL/Linux 下交叉构建：

```bash
npm run dist:win:wsl
```

默认会做两件事：

- 编译 `x86_64-pc-windows-msvc` 目标
- 跳过安装包，仅生成可执行文件

输出目录：

```text
src-tauri/target/x86_64-pc-windows-msvc/release/
```

当前仅生成：

- Windows x64 便携版 `.exe`
- 不生成安装包

## GitHub Actions 多平台发布

仓库内的 `.github/workflows/release.yml` 会构建并发布以下产物：

- Windows x64：NSIS 安装包和便携版 `.exe`
- macOS ARM64（Apple Silicon）：DMG 和应用归档
- macOS x86_64（Intel）：DMG 和应用归档

发布前，需要确保以下三个文件中的版本号一致：

- `package.json`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`

提交版本修改后，推送对应的 `v` 开头标签即可发布：

```bash
git tag v1.0.0
git push origin v1.0.0
```

也可以在 GitHub 的 Actions 页面手动运行 `Build and release`，输入与应用版本一致的标签。工作流会先创建草稿 Release，全部平台构建成功后再正式发布；如果任一平台失败，Release 会保留为草稿，修复后可重新运行。

当前工作流未配置 Windows 或 Apple 代码签名。未签名的安装包仍可构建和下载，但 Windows SmartScreen 或 macOS Gatekeeper 可能显示安全提示。

## 数据存储位置

SQLite 保存在 Tauri 的应用配置目录中。  
Windows 下通常位于 `%APPDATA%/io.github.mino9526.authenticator/` 一类目录，数据库文件名为：

```text
authenticator.sqlite
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
src-tauri/     Tauri 2 Rust 入口、能力配置、图标与原生插件接入
src/           前端逻辑、Tauri 插件接入、TOTP 处理与纯逻辑测试
vite.config.js Vite 配置
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
