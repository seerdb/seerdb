<!-- SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->

# seerdb

> 本页是简体中文简介。英文 [README](README.md) 为准，兼容性表、功能列表和
> 使用说明均在其中。

seerdb 是一个纯 Python 实现的项目，实现了一种专有数据库的线协议（TNS/TTC），
包括客户端和服务器两端，无需任何厂商客户端库：

- **客户端**：符合 [DB-API 2.0](https://peps.python.org/pep-0249/) 的驱动，
  通过 TCP 直接与数据库通信，支持 8i 至 26ai 版本。
- **Mirror（服务器端）**：让该数据库的客户端（如 sqlplus、python-oracledb）
  连接到 PostgreSQL。SQL 和 PL/SQL 在到达时即被翻译，因此现有应用程序无需修改
  即可在 PostgreSQL 上运行，便于逐步完成迁移。Mirror 目前是初始实现，
  在正式发布（GA）之前属于技术预览版，尚不适用于生产环境。

## 安装

```sh
pip install seerdb            # 客户端
pip install "seerdb[mirror]"  # 加上 Mirror 的 PostgreSQL 后端
```

## 文档（英文）

- [README](README.md)：兼容性、功能、快速入门
- [docs/MIRROR.md](docs/MIRROR.md)：Mirror 使用指南
- [docs/PROTOCOL.md](docs/PROTOCOL.md)：线协议说明

## 许可证与商标

本项目采用 MIT 许可证。Oracle 和 Oracle Database 是 Oracle 公司及其关联公司的
商标或注册商标。seerdb 是独立项目，与 Oracle 无关联，仅为互操作性而实现该协议。
