<p align="center">
  <img src="src-tauri/icons/icon.png" width="120" height="120" alt="TOTP Authenticator 图标">
</p>

<h1 align="center">TOTP Authenticator</h1>

<p align="center">
  基于 Tauri 2 与 SQLite 的本地优先桌面 TOTP 认证器。
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
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS-informational" alt="Windows 和 macOS">
  <img src="https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white" alt="Tauri 2">
</p>

## 项目简介

TOTP Authenticator 用于在桌面端管理并生成基于时间的一次性密码。应用数据保存在本机 SQLite 数据库中，验证码也在本地计算；发布版不依赖本地 HTTP 服务或远程后端。

项目使用原生 HTML、CSS 和 JavaScript 构建界面，以 Tauri 2 提供桌面运行时、文件对话框、安全外链与 SQLite 持久化能力。

## 功能亮点

- 实时生成 TOTP 验证码并显示环形倒计时
- 点击条目即可复制当前验证码
- 支持添加、编辑、删除和按密钥去重
- 支持解析 `otpauth://totp/...` URI 与 Base32 密钥
- 支持 SHA-1、SHA-256、SHA-512 算法
- 支持 6 位或 8 位验证码，以及 15、30、45、60 秒周期
- 支持为条目添加备注和 HTTP(S) 网站链接
- 使用 SQLite 在本机持久化数据
- 支持 JSON 备份导出、恢复与合并
- 核心功能可完全离线使用

## 下载

前往 [GitHub Releases](https://github.com/Mino9526/authenticator/releases/latest) 下载最新版本。

| 平台 | 架构 | 发布产物 |
| --- | --- | --- |
| Windows | x86_64 | NSIS 安装包、便携版 EXE |
| macOS | ARM64 / Apple Silicon | DMG、应用归档 |
| macOS | x86_64 / Intel | DMG、应用归档 |

> [!NOTE]
> 当前发布产物尚未配置 Windows 或 Apple 代码签名，因此 Windows SmartScreen 或 macOS Gatekeeper 可能显示安全提示。

## 基本使用

1. 从 Releases 下载适合当前平台的版本并安装或解压。
2. 点击右下角的 `+` 新增条目。
3. 粘贴 `otpauth://totp/...` URI 或 Base32 密钥，也可以手动补充名称、账号和备注。
4. 点击条目复制验证码；点击网站图标打开关联网址；点击右侧菜单编辑或删除条目。
5. 使用顶部的导入、导出功能备份或恢复数据。

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
| `npm test` | 运行 TOTP 与数据校验测试 |

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
3. 并行构建 Windows x64、macOS ARM64 和 macOS x86_64。
4. 上传安装包、便携程序和应用归档。
5. 所有平台成功后才将草稿转为正式 Release。

发布前请同步更新以下版本：

- `package.json` 与 `package-lock.json`
- `src-tauri/Cargo.toml` 与 `src-tauri/Cargo.lock`
- `src-tauri/tauri.conf.json`

提交版本修改后创建并推送标签：

```bash
git tag vX.Y.Z
git push origin master vX.Y.Z
```

也可以在仓库的 Actions 页面手动运行工作流，并输入与应用版本一致的标签。如果某个平台构建失败，Release 会保留为草稿，修复后可以重新发布新版本。

## 数据与备份

数据库文件名为 `authenticator.sqlite`，保存在 Tauri 为应用分配的本机配置目录中，具体路径随操作系统而异。

导出的 JSON 备份包含完整条目数据。导入时会根据条目指纹进行合并：新条目会加入数据库，匹配的现有条目会被备份内容更新。

<details>
<summary>查看备份格式示例</summary>

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
      "secret": "YOUR_BASE32_SECRET",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "notes": "恢复码已保存在安全位置",
      "website": "https://github.com/settings/security",
      "createdAt": 1711948800000,
      "updatedAt": 1711948800000
    }
  ]
}
```

</details>

## 安全说明

> [!WARNING]
> 当前版本不会额外加密 SQLite 中的 TOTP 密钥，JSON 备份也包含明文密钥。请勿公开数据库、备份文件、日志或包含真实密钥的截图。

- 应用不会将条目或验证码上传到远程服务。
- 条目网站仅允许使用 `http://` 或 `https://` 协议。
- 建议使用操作系统磁盘加密，并将备份保存在受保护的位置。
- 在正式生产环境分发前，建议配置 Windows 与 Apple 代码签名。

## 项目结构

```text
.
├── .github/workflows/   GitHub Actions 构建与发布
├── src/                 前端交互、存储接入与 TOTP 逻辑
├── src-tauri/           Tauri 入口、权限、SQLite 与原生资源
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
