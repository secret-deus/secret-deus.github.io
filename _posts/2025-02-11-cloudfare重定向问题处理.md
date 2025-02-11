---
title: cloudfare重定向问题处理
date: 2025-02-11 22:33:00 +0800
categories: [Deploy]
tags: [部署]     # TAG names should always be lowercase
---

## 问题
今天给GitHub Page套了层Cloudflare，结果访问时浏览器报“重定向次数过多”错误。
## 原因
通过百度查询，发现是HTTPS的问题。GitHub Page中打开了“Enforce HTTPS ”，这会让所有HTTP的链接重定向到HTTPS中。而Cloudflare回源使用的是HTTP链接，于是就出现了一遍遍的重定向，最终次数过多浏览器报错。
## 解决方案
将Cloudflare中的SSL/TLS 加密模式由“关闭”或“灵活”改为“完全”即可。