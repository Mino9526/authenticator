<p align="center">
  <img src="src-tauri/icons/icon.png" width="120" height="120" alt="TOTP Authenticator 图标">
</p>

<h1 align="center">TOTP Authenticator</h1>

<p align="center">
  基于 Tauri 2、Rust 与加密 SQLite 存储的本地优先桌面 TOTP 认证器。
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

TOTP Authenticator 用于在桌面端管理并生成基于时间的一次性密码。条目在写入本机 SQLite 前会由 Rust 后端加密，验证码也只在 Rust 后端计算；发布版不依赖本地 HTTP 服务或远程后端。

项目采用原生 HTML、CSS 和 JavaScript 构建轻量界面，并通过 Tauri 2 集成 Rust 核心，可在 Windows、macOS 和 Linux 上运行。

## 功能亮点

- 实时生成 TOTP 验证码并显示环形倒计时
- 点击条目即可复制当前验证码
- 支持添加、编辑、删除和按密钥去重
- 支持解析 `otpauth://totp/...` URI 与 Base32 密钥
- 支持 SHA-1、SHA-256、SHA-512 算法
- 支持 6 位或 8 位验证码，以及 15、30、45、60 秒周期
- 支持为条目添加备注和 HTTP(S) 网站链接
- 使用 Argon2id 与 XChaCha20-Poly1305 保护本机保险库
- 支持主密码修改、手动锁定与 5 分钟闲置自动锁定
- 使用 SQLite 在本机持久化加密后的完整条目
- 支持独立密码保护的加密备份、恢复与按密钥合并
- 支持导入旧版明文 JSON 备份与 `otpauth://` 文本
- 复制验证码 30 秒后自动清空未被覆盖的剪贴板内容
- 核心功能可完全离线使用

## 下载

前往 [GitHub Releases](https://github.com/Mino9526/authenticator/releases/latest) 下载最新版本。

| 平台 | 架构 | 发布产物 |
| --- | --- | --- |
| Windows | x64 | `authenticator-1.1.2-windows-x64.exe`、`authenticator-1.1.2-windows-x64.zip` |
| macOS | ARM64 / Apple Silicon | `authenticator-1.1.2-macos-arm64.dmg` |
| macOS | x64 / Intel | `authenticator-1.1.2-macos-x64.dmg` |
| Linux | x64 | `authenticator-1.1.2-linux-x64.AppImage`、`authenticator-1.1.2-linux-x64.deb`、`authenticator-1.1.2-linux-x64.rpm` |
| Linux | ARM64 | `authenticator-1.1.2-linux-arm64.AppImage`、`authenticator-1.1.2-linux-arm64.deb`、`authenticator-1.1.2-linux-arm64.rpm` |

Windows 的 `.exe` 是 NSIS 安装包，`.zip` 是便携版压缩包。Linux 用户可以选择通用的 AppImage、适用于 Debian/Ubuntu 系发行版的 `.deb`，或适用于 Fedora/RHEL/openSUSE 系发行版的 `.rpm`；首次运行 AppImage 前需要为文件添加可执行权限。

> [!NOTE]
> 当前发布产物尚未配置 Windows 或 Apple 代码签名，因此 Windows SmartScreen 或 macOS Gatekeeper 可能显示安全提示。

## 基本使用

1. 从 Releases 下载适合当前平台的版本并安装或解压。
2. 首次启动时设置至少 8 个字符的主密码；从旧版本升级时，已有明文条目会在此时自动加密迁移。
3. 点击右下角的 `+` 新增条目。
4. 粘贴 `otpauth://totp/...` URI 或 Base32 密钥，也可以手动补充名称、账号和备注。
5. 点击条目复制验证码；点击网站图标打开关联网址；点击右侧菜单编辑或删除条目。
6. 使用顶部菜单导入或导出加密备份，也可以修改主密码或立即锁定保险库。

> [!IMPORTANT]
> 主密码和备份密码均无法找回。遗忘主密码会导致本机保险库无法解锁；遗忘备份密码会导致对应备份无法恢复。

## 本地开发

### 环境要求

- [Node.js](https://nodejs.org/) 22 或更高版本
- [Rust](https://www.rust-lang.org/tools/install) stable toolchain
- 当前操作系统对应的 [Tauri 2 系统依赖](https://v2.tauri.app/start/prerequisites/)

### 启动项目

```bash
git clone https://github.com/Mino9526/authenticator.git
cd authenticator
npm ci
npm start
```

`npm start` 会同时启动 Tauri 开发模式与 Vite 开发服务器。开发页面默认运行在 `http://localhost:1420`；发布构建会将前端静态资源直接打包进桌面应用。

### 常用命令

| 命令 | 说明 |
| --- | --- |
| `npm start` | 启动完整的 Tauri 桌面开发环境 |
| `npm run dev` | 仅启动 Vite 前端开发服务器 |
| `npm run build` | 构建前端生产资源 |
| `npm run tauri -- build` | 为当前操作系统构建原生应用 |
| `npm test` | 运行前端解析、校验与安全边界测试 |
| `cargo test --manifest-path src-tauri/Cargo.toml` | 运行加密、TOTP、迁移与备份测试 |

## 本地原生构建

在完成当前操作系统的 Tauri 环境配置后执行：

```bash
npm ci
npm run tauri -- build
```

默认产物位于：

```text
src-tauri/target/release/bundle/
```

跨平台正式产物由 GitHub Actions 在对应的原生 runner 上构建，本地只需配置当前操作系统的开发环境。

## 自动构建与发布

[Build and release](.github/workflows/release.yml) 工作流支持标签触发和手动触发，发布过程如下：

1. 校验 npm、Cargo 与 Tauri 版本号。
2. 创建或复用草稿 Release。
3. 并行构建 Windows x64、macOS x64/ARM64 和 Linux x64/ARM64。
4. 按 `authenticator-{版本}-{操作系统}-{CPU 架构}.{扩展名}` 命名并上传安装包、便携压缩包和应用镜像。
5. 所有平台成功后才将草稿转为正式 Release。

Release 名称与版本标签保持一致，例如标签 `v1.1.2` 对应的 Release 名称也是 `v1.1.2`。

发布前请同步更新以下版本：

- `package.json` 与 `package-lock.json`
- `src-tauri/Cargo.toml` 与 `src-tauri/Cargo.lock`
- `src-tauri/tauri.conf.json`

提交版本修改后创建并推送标签：

```bash
git tag -s vX.Y.Z -m "TOTP Authenticator vX.Y.Z"
git push origin master vX.Y.Z
```

也可以在仓库的 Actions 页面手动运行工作流，并输入与应用版本一致的标签。如果某个平台构建失败，Release 会保留为草稿，修复后可以重新发布新版本。

## 数据与备份

数据库文件名为 `authenticator.sqlite`，保存在 Tauri 为应用分配的本机配置目录中，具体路径随操作系统而异。数据库中的完整条目被序列化后使用随机数据密钥加密；数据库只保留密文、随机 nonce、带密钥的去重指纹和必要的时间字段。

- 每个保险库使用独立的随机 256 位数据密钥。
- 主密码通过 Argon2id 派生密钥，并只用于包装数据密钥；应用不会保存主密码。
- 条目和备份使用 XChaCha20-Poly1305 加密并校验完整性。
- 修改主密码只重新包装数据密钥，不会将所有条目解密后重新写入。
- 导出的 `.totp` 文件使用独立备份密码，不依赖创建备份的设备。
- 恢复时根据 Secret 的带密钥指纹合并；匹配条目会更新，新条目会加入当前保险库。
- 旧版明文 JSON 和逐行 `otpauth://` 文本仅支持导入，不再支持明文导出。

<details>
<summary>查看加密备份容器示例</summary>

```json
{
  "format": "totp-authenticator-backup",
  "version": 1,
  "createdAt": 1711948800000,
  "appVersion": "...",
  "kdf": {
    "name": "argon2id",
    "memoryKib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "..."
  },
  "cipher": {
    "name": "xchacha20poly1305",
    "nonce": "..."
  },
  "ciphertext": "..."
}
```

</details>

### 从旧版本升级

检测到旧版 `entries` 明文表时，应用会在创建保险库的同一个数据库事务中完成读取、加密、回读校验和旧表移除。任一步骤失败都会回滚，不会留下部分迁移状态；成功后还会清理 SQLite 的旧页面与 WAL。

迁移后的数据库不兼容未提供保险库支持的旧版应用，请勿在同一数据目录上降级运行。升级前仍建议保留一份安全存放的旧版备份，确认新版本能够解锁后再删除。

## 安全说明

- 应用不会将条目或验证码上传到远程服务。
- TOTP Secret 的持久化、解密和验证码计算均位于 Rust 后端。
- 已保存的 TOTP Secret 不会返回 WebView；前端只接收条目展示信息、当前验证码与剩余时间。
- 解锁密钥只保留在进程内存中，锁定时会进行零化处理。
- 保险库默认闲置 5 分钟后锁定，也可以通过顶部菜单立即锁定。
- 条目网站仅允许使用 `http://` 或 `https://` 协议。
- 加密主要保护设备丢失、数据库或备份文件泄露等静态数据风险；无法抵御保险库解锁期间已经控制当前用户会话的恶意软件。
- 仍建议启用 BitLocker 或 FileVault，并避免公开数据库、备份文件、日志或包含真实验证码的截图。
- 在正式生产环境分发前，建议配置 Windows 与 Apple 代码签名。

## 项目结构

```text
.
├── .github/workflows/   GitHub Actions 构建与发布
├── src/                 前端交互、保险库调用与输入校验
├── src-tauri/           Rust 保险库、TOTP、加密备份、SQLite 与原生资源
├── index.html           应用页面结构
├── styles.css           界面样式
├── vite.config.js       Vite 开发与构建配置
└── package.json         前端依赖和项目命令
```

## 参与贡献

欢迎通过 [Issues](https://github.com/Mino9526/authenticator/issues) 报告问题或提出建议，也欢迎提交 Pull Request。

提交代码前请至少运行：

```bash
npm test
npm run build
```

如果修改了桌面端依赖、权限或打包配置，建议同时在受影响的操作系统上运行一次原生构建。

## 许可证

本项目采用 [MIT License](LICENSE) 开源。你可以自由使用、修改、分发和商用本项目，但需要保留原始版权与许可证声明。
