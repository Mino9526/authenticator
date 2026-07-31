<p align="center">
  <img src="src-tauri/icons/icon.png" width="120" height="120" alt="TOTP Authenticator 图标">
</p>

<h1 align="center">TOTP Authenticator</h1>

<p align="center">
  本地优先、跨平台的桌面 TOTP 认证器，以 Rust 保护密钥并在 SQLite 中保存密文。
</p>

<p align="center">
  <a href="https://github.com/Mino9526/authenticator/actions/workflows/release.yml">
    <img src="https://github.com/Mino9526/authenticator/actions/workflows/release.yml/badge.svg" alt="Build and release">
  </a>
  <a href="https://github.com/Mino9526/authenticator/releases">
    <img src="https://img.shields.io/github/v/release/Mino9526/authenticator?display_name=tag" alt="GitHub Release">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/Mino9526/authenticator" alt="MIT License">
  </a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational" alt="Windows、macOS 和 Linux">
  <img src="https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white" alt="Tauri 2">
</p>

## 项目简介

TOTP Authenticator 用于在桌面端保存账户并生成基于时间的一次性密码。正式构建不依赖远程服务或本地 HTTP 服务，保险库的持久化、解密和验证码计算均由 Rust 后端完成。

界面使用原生 HTML、CSS 和 JavaScript 构建，通过 Tauri 2 集成为 Windows、macOS 和 Linux 原生应用。项目强调轻量、离线可用，以及清晰的前后端敏感数据边界。

## 功能

### 验证器

- 添加、编辑、删除和按 Secret 去重
- 解析 `otpauth://totp/...` URI 与 Base32 Secret
- 支持 SHA-1、SHA-256、SHA-512
- 支持 6 位或 8 位验证码
- 支持 15、30、45、60 秒周期
- 实时显示验证码和环形倒计时
- 点击条目复制验证码，并在 30 秒后清理未被覆盖的剪贴板内容
- 支持备注与 HTTP(S) 网站链接

### 保险库与备份

- 使用 Argon2id 与 XChaCha20-Poly1305 保护本机保险库
- 使用 SQLite 持久化加密后的完整条目
- 支持修改主密码、手动锁定和 5 分钟闲置自动锁定
- 支持使用独立密码创建和恢复 `.totp` 加密备份
- 恢复备份时按 Secret 的带密钥指纹合并重复条目
- 支持导入旧版明文 JSON 备份和逐行 `otpauth://` 文本
- 检测并事务化迁移当前数据目录中的旧版明文 `entries` 表

## 下载

前往 [GitHub Releases](https://github.com/Mino9526/authenticator/releases/latest) 下载适合当前平台的最新构建。

| 平台 | 架构 | 发布文件 |
| --- | --- | --- |
| Windows | x64 | `authenticator-{version}-windows-x64.exe`、`authenticator-{version}-windows-x64.zip` |
| macOS | ARM64 / Apple Silicon | `authenticator-{version}-macos-arm64.dmg` |
| macOS | x64 / Intel | `authenticator-{version}-macos-x64.dmg` |
| Linux | x64 | `authenticator-{version}-linux-x64.AppImage`、`authenticator-{version}-linux-x64.deb`、`authenticator-{version}-linux-x64.rpm` |
| Linux | ARM64 | `authenticator-{version}-linux-arm64.AppImage`、`authenticator-{version}-linux-arm64.deb`、`authenticator-{version}-linux-arm64.rpm` |

`{version}` 表示不带 `v` 前缀的应用版本。Windows 的 `.exe` 是 NSIS 安装包，`.zip` 是便携版压缩包；Linux 用户可以根据发行版选择 AppImage、DEB 或 RPM。

首次运行 AppImage 前需要添加可执行权限：

```bash
chmod +x authenticator-*-linux-*.AppImage
```

> [!NOTE]
> 当前发布文件尚未配置 Windows 或 Apple 代码签名，因此 Windows SmartScreen 或 macOS Gatekeeper 可能显示安全提示。

## 快速开始

1. 从 Releases 下载并安装或解压对应平台的构建。
2. 首次启动时设置至少 8 个字符的主密码。
3. 点击右下角的 `+`，粘贴 `otpauth://totp/...` URI 或 Base32 Secret。
4. 根据需要补充名称、账号、备注和网站。
5. 点击条目复制当前验证码，或通过条目菜单进行编辑和删除。
6. 使用顶部菜单导入、导出备份，修改主密码或立即锁定保险库。

> [!IMPORTANT]
> 应用不会保存主密码，也不提供密码找回能力。遗忘主密码将无法解锁本机保险库；遗忘备份密码将无法恢复对应备份。

## 安全设计

```text
HTML / CSS / JavaScript
          │ Tauri commands
          ▼
Rust 保险库、输入校验与 TOTP 计算
          │ encrypted records
          ▼
        SQLite
```

- 应用不会主动将条目、Secret 或验证码上传到远程服务。
- 已保存的 Secret 不会返回 WebView；前端只接收展示信息、当前验证码和剩余时间。
- 每个保险库使用独立的随机 256 位数据密钥。
- 主密码通过 Argon2id 派生密钥，并只用于包装数据密钥。
- 条目和备份使用 XChaCha20-Poly1305 加密并校验完整性。
- 修改主密码只重新包装数据密钥，不会逐条重新加密。
- 解锁密钥只保留在进程内存中，锁定时会进行零化处理。
- 条目网站仅允许 `http://` 和 `https://` 协议。

这些措施主要保护设备丢失、数据库泄露和备份文件泄露等静态数据风险，不能抵御保险库解锁期间已经控制当前用户会话的恶意软件。建议同时启用 BitLocker、FileVault 或同类全盘加密，并避免公开数据库、备份、日志或包含真实验证码的截图。

## 数据、备份与迁移

数据库文件名为 `authenticator.sqlite`，位于 Tauri 为应用分配的本机配置目录中。数据库只保存密文、随机 nonce、带密钥的去重指纹和必要的时间字段。

导出的 `.totp` 文件使用独立备份密码，不依赖创建备份的设备。恢复时，匹配的条目会更新，新条目会加入当前保险库。旧版明文 JSON 与逐行 `otpauth://` 文本仅支持导入，不再支持明文导出。

如果当前数据库中存在旧版明文 `entries` 表，创建保险库时会在同一个数据库事务中完成读取、加密、回读校验和旧表移除。任一步骤失败都会回滚；成功后还会清理 SQLite 的旧页面与 WAL。

迁移后的数据库不兼容未提供保险库支持的旧版应用。升级前建议保留一份安全存放的备份，确认新版本能够正常解锁后再删除。

## 技术栈

| 层级 | 技术 |
| --- | --- |
| 桌面运行时 | Tauri 2 |
| 界面 | HTML、CSS、JavaScript、Vite |
| 核心逻辑 | Rust |
| 数据存储 | SQLite、SQLx |
| 密钥派生与加密 | Argon2id、XChaCha20-Poly1305、HKDF |

## 本地开发

### 环境要求

- [Node.js](https://nodejs.org/) 22 或更高版本
- [Rust](https://www.rust-lang.org/tools/install) stable toolchain
- 当前操作系统对应的 [Tauri 2 系统依赖](https://v2.tauri.app/start/prerequisites/)

### 启动

```bash
git clone https://github.com/Mino9526/authenticator.git
cd authenticator
npm ci
npm start
```

`npm start` 会启动 Tauri 开发模式与 Vite 开发服务器。前端开发服务器默认监听 `http://localhost:1420`，正式构建会将静态资源直接打包进应用。

### 常用命令

| 命令 | 说明 |
| --- | --- |
| `npm start` | 启动完整桌面开发环境 |
| `npm run dev` | 仅启动 Vite 前端开发服务器 |
| `npm run build` | 构建前端生产资源 |
| `npm run tauri -- build` | 为当前操作系统构建原生应用 |
| `npm test` | 运行前端测试 |
| `cargo test --manifest-path src-tauri/Cargo.toml` | 运行 Rust 加密、TOTP、迁移与备份测试 |

## 构建

安装当前操作系统所需的 Tauri 依赖后执行：

```bash
npm ci
npm run tauri -- build
```

原生构建通常输出到 `src-tauri/target/release/bundle/`；显式指定 Rust target 时，产物位于对应 target 子目录。跨平台正式构建由 GitHub Actions 在各平台的原生 runner 上完成。

## 发布流程

[Build and release](.github/workflows/release.yml) 工作流可由 `vX.Y.Z` 标签或手动操作触发：

1. 校验 npm、Cargo 与 Tauri 配置中的版本一致性。
2. 创建或复用以标签命名的草稿 Release。
3. 并行构建 Windows x64、macOS x64/ARM64 和 Linux x64/ARM64。
4. 生成 NSIS、DMG、AppImage、DEB、RPM 与 Windows 便携压缩包。
5. 按 `authenticator-{version}-{os}-{arch}.{extension}` 命名发布文件。
6. 所有构建成功后发布 Release；任一平台失败则保留草稿。

发布前需要同步更新：

- `package.json` 与 `package-lock.json`
- `src-tauri/Cargo.toml` 与 `src-tauri/Cargo.lock`
- `src-tauri/tauri.conf.json`

创建签名标签并推送：

```bash
git tag -s vX.Y.Z -m "TOTP Authenticator vX.Y.Z"
git push origin master vX.Y.Z
```

## 项目结构

```text
.
├── .github/workflows/   GitHub Actions 构建与发布
├── src/                 前端交互、Tauri 调用与输入校验
├── src-tauri/           Rust 保险库、TOTP、SQLite 与原生资源
├── index.html           页面结构
├── styles.css           界面样式
├── vite.config.js       Vite 配置
└── package.json         项目元数据、依赖与命令
```

## 参与贡献

欢迎通过 [Issues](https://github.com/Mino9526/authenticator/issues) 报告问题或提出建议，也欢迎提交 Pull Request。

提交前请至少运行：

```bash
npm test
npm run build
```

如果修改了 Rust 后端、权限、依赖或打包配置，请同时运行 Rust 测试，并尽可能在受影响的平台执行一次原生构建。

## 许可证

本项目采用 [MIT License](LICENSE)。你可以自由使用、修改、分发和商用本项目，但需要保留原始版权与许可证声明。
