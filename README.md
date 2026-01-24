<img src="https://www.lik.cc/upload/icon.svg" 
     style="width: 200px;  
            height: auto;      
            margin: 0 px;   
            vertical-align: text-bottom;"
     alt="Halo AI Copilot 图标">

# Halo AI Copilot - 智能续写助手

> 类 GitHub Copilot 的文章自动补全插件，提供流畅的 AI 续写体验。
>
> 📦 [GitHub源码](https://github.com/acanyo/halo-plugin-summaraidGPT)

# 💬交流
![群.png](https://www.lik.cc/upload/iShot_2025-03-03_16.03.00.png)

> 📌 本插件积极维护，欢迎通过 [Issue](https://github.com/acanyo/halo-plugin-summaraidGPT/issues) 提交需求或参与共建！

## 🚀 核心功能

### 📝 智能续写 (Article Completion)
- **非侵入式体验**：模仿 GitHub Copilot，在你停止打字时自动触发。
- **幽灵文字 (Ghost Text)**：以灰色文字在光标后显示建议，不干扰正常视线。
- **一键采纳**：按下 `Tab` 键即可将建议内容插入文章。
- **极速响应**：支持国内加速站及 DeepSeek 等高性能模型。

### 🤖 多AI服务支持
- **DeepSeek** - 推荐使用，高性价比，更懂中文语境
- **OpenAI** - GPT-4o、GPT-4o-mini 等
- **智谱AI** - GLM-4.5 系列
- **通义千问** - Qwen 系列
- **硅基流动** - 支持多种开源模型
- **Codesphere** - 国内加速站

---

## 📥 安装指南

1. **下载安装**：
   - 进入 [Releases](https://github.com/acanyo/halo-plugin-summaraidGPT/releases) 下载最新版本的 `.jar` 包。
   - 在 Halo 后台「插件」页面上传安装。
2. **启用插件**：
   - 安装完成后，启用 "Halo AI Copilot" 插件。

## ⚙️ 配置说明

进入 **插件 -> Halo AI Copilot -> 设置**：

### 1. AI 设置
选择您偏好的 AI 提供商并填写 API Key。
- **推荐**：使用 **DeepSeek** 或 **硅基流动**，在中文续写场景下表现优异且成本低廉。

### 2. 补全设置 (可选)
- **系统提示词 (System Prompt)**：虽然插件内置了经过调优的“强制续写”提示词，但您仍可以在此自定义 AI 的人设。若非专业需求，建议留空。

## 🎯 使用指南

1. 打开文章编辑器（Halo 默认富文本编辑器）。
2. 开始书写文章。
3. 当您**停止打字超过 2 秒**时，AI 会自动读取光标前的上下文。
4. 若 AI 认为有合适的续写内容，会以**灰色文字**显示在光标后。
5. **按下 `Tab` 键**：采纳建议。
6. **按下 `Esc` 键**或继续打字：忽略建议。

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进项目！

## 📄 许可证

本项目基于 GPL-3.0 许可证开源 - 查看 [LICENSE](LICENSE) 文件了解详情
