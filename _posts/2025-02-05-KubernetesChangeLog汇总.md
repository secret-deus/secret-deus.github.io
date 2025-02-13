---
title: KubernetesChangelogs
date: 2025-02-05 17:00:00 +0800
categories: [kubernetes]
tags: [知识梳理]     # TAG names should always be lowercase
---

### **Kubernetes 1.24**

**发布日期：** 2022年5月3日
**主要更新：**

- **移除 Dockershim：**  v1.20 中被弃用的 Dockershim 组件已从 kubelet 中移除。用户需迁移至其他受支持的容器运行时，如 containerd 或 CRI-O。
- **默认关闭 Beta API：** 的 Beta API 默认不再启用，现有的 Beta API 及其更新版本仍保持启用。
- **签署发布工件：** 入了使用 cosign 对发布工件进行签名的机制，增强了软件供应链的安全性。
- **OpenAPI v3 支持：** 供了以 OpenAPI v3 格式发布 API 的 Beta 支持。
- **存储容量跟踪和卷扩展：** 储容量跟踪和卷扩展功能已达到稳定版，改进了存储管理能力。
- **非抢占优先级：**  PriorityClasses 添加了非抢占选项，提供了更灵活的调度策略。
- **存储插件迁移：** zure Disk 和 OpenStack Cinder 插件已迁移至 CSI 驱动程序。
- **gRPC 探针：** RPC 探测功能升级至 Beta，允许为 gRPC 应用程序配置启动、存活和就绪性探测。
- **Kubelet 凭证提供者：** ubelet 对镜像凭证提供者的支持已升级到 Beta，允许动态检索容器镜像仓库的凭据。
- **上下文日志记录：** 入了上下文日志记录功能，使函数调用者能够控制日志记录的各个方面。
- **避免服务 IP 分配冲突：** 入了新的功能，允许为服务的静态 IP 地址分配软保留范围，降低冲突风险。
- **移除动态 Kubelet 配置：** 态 Kubelet 配置已从 kubelet 中移除，并计划在 Kubernetes 1.26 中从 API 服务器中移除。
多详细信息，请参阅官方发布公告。citeturn0search10
---

### **Kubernetes 1.25**

**发布日期：** 2022年8月23日
**主要更新：**

- **Pod 安全性准入：** odSecurity 准入控制器已达到稳定版，提供了基于命名空间标签的安全策略。
- **容器运行时接口（CRI）增强：**  CRI 进行了改进，增强了对多种容器运行时的兼容性。
- **存储功能增强：** SI 插件支持更多的存储后端，并增强了与动态卷供给的兼容性。
- **资源请求和限制优化：** 进了资源请求与限制的计算和调度，提升了调度器的资源分配能力。
- **弃用 PodSecurityPolicy（PSP）：** SP 功能被正式弃用，用户应迁移到新的 PodSecurity 策略。
- **移除 `--cloud-provider` 标志：** --cloud-provider` 标志被移除，用户需迁移到新的云提供商接口。
- **服务账户权限策略调整：** 服务账户的权限策略进行了改进，部分权限不再默认开放。
- **API 版本更新：** 些旧的 API 版本被废弃，用户需迁移到更稳定的版本。
多详细信息，请参阅官方发布公告。
---

### **Kubernetes 1.26**

**发布日期：** 2022年12月8日
**主要更新：**

- **原生边车容器支持：** 入了原生的边车容器支持，简化了边车容器的管理。
- **Job 控制器增强：**  Job 控制器进行了增强，支持更多的调度和重试策略。
- **存储功能增强：** 入了对新的存储卷模式和快照功能的支持。
- **弃用旧版 API：** 一步弃用了旧的 API 版本，用户需尽快迁移到新的 API。
- **安全性增强：** 强了对证书和密钥管理的控制，提升了集群的安全性。
多详细信息，请参阅官方发布公告。
---

### **Kubernetes 1.27**

**发布日期：** 2023年4月11日
**主要更新：**

- **控制器管理器的领导者迁移：** ube-controller-manager 和 cloud-controller-manager 可以在高可用控制平面中重新分配新的控制器，无需停机。
- **Pod 亲和性 NamespaceSelector：**  Pod 亲和性/反亲和性规则添加了 `namespaceSelector` 字段。
- **弃用旧版 API：** 续弃用旧的 API 版本，用户需迁移到新的 API。
- **安全性增强：** 进了对服务账户和 RBAC 的支持，增强了权限管理。
多详细信息，请参阅官方发布公告。
---

### **Kubernetes 1.28**

**发布日期：** 2023年8月16日
**主要更新：**

1. **节点非体面关闭功能进入 GA（正式发布）阶段：**
   - 特性允许在节点意外关闭或不可恢复时，有状态工作负载能够在其他节点上重新启动，确保应用的高可用性。citeturn0search0
2. **对 Linux 上交换内存的 Beta 支持：**
   - 入了对 Linux 节点上交换内存的支持，提升了节点的内存管理能力，增强了系统的稳定性。citeturn0search2
3. **Job 失效处理的改进：**
   - 入了 Pod 更换策略和基于索引的回退限制，改进了对批处理作业中 Pod 失效的处理，提高了批处理任务的可靠性。citeturn0search6
4. **节点 podresources API 正式发布：**
   -  API 允许用户查询节点上分配给容器的资源信息，增强了对资源分配的可观测性。citeturn0search14
5. **用于改进集群安全升级的新机制（Alpha）：**
   - 入了混合版本代理特性，允许在集群升级期间，不同版本的 API 服务器之间正确处理资源请求，确保升级过程的平滑和安全。citeturn0search13
---

### **Kubernetes 1.29**

**发布日期：** 2023年12月13日
**主要更新：**

1. **引入 nftables 作为 kube-proxy 的新后端（Alpha）：**
   -  kube-proxy 添加了基于 nftables 的后端，以替代传统的 iptables，提供更好的性能和可扩展性。citeturn0search4
2. **Sidecar 容器功能进入 Beta 阶段并默认启用：**
   - idecar 容器运行模式进入了 Beta 阶段，允许用户明确定义 Sidecar 容器的启动顺序和生命周期管理，增强了对应用程序的支持。citeturn0search11
3. **KMS v2 静态加密功能正式发布：**
   - MS v2 提供了性能提升、密钥轮换和可观测性方面的改进，为集群中的数据加密提供了更可靠的解决方案。citeturn0search7
4. **ReadWriteOncePod 持久卷访问模式达到稳定版：**
   - 入了新的持久卷访问模式，确保在整个集群中，只有一个 Pod 可以读写特定的 PVC，增强了数据的安全性和一致性。citeturn0search10
5. **上下文日志记录功能的增强：**
   - 进了日志记录机制，引入了上下文日志记录功能，提供了更好的故障排除能力和增强的日志记录。citeturn0search3
6. **Service 负载均衡器 IP 模式（Alpha）：**
   - 入了新的 Alpha 特性，允许用户配置 Service 的负载均衡器 IP 模式，提供了更灵活的流量管理方式。citeturn0search4
---
抱歉之前的总结遗漏了 Kubernetes 1.30 和 1.31 版本的更新日志。以下是对这两个版本的中文总结：

---

### **Kubernetes 1.30**

**发布日期：** 2024年3月12日
**主要更新：**

1. **动态资源分配（DRA）结构化参数：**
   -  DRA 进行了扩展，引入了结构化参数支持，增强了资源请求的透明性和可管理性。
2. **节点交换内存（Swap）支持：**
   - 进了 Linux 节点的交换内存支持，默认启用了 `NodeSwap` 特性门控，并将默认行为设置为 `NoSwap` 模式，提升了系统稳定性。
3. **用户命名空间支持：**
   - 用户命名空间的支持升级至 Beta，允许在容器内以非特权用户运行进程，增强了安全性。
4. **结构化身份认证配置：**
   - 入了基于文件的身份认证配置，支持配置多个 JWT 认证组件，提供了更灵活的认证机制。
5. **基于容器资源指标的 Pod 自动扩缩容：**
   - 许根据各个容器的资源使用情况配置自动扩缩容策略，提升了资源利用效率。
6. **在准入控制中使用 CEL：**
   - 成了通用表达式语言（CEL）用于准入控制，提供了更动态和细粒度的策略控制能力。
多详细信息，请参阅官方发布公告。
---

### **Kubernetes 1.31**

**发布日期：** 2024年8月13日
**主要更新：**

1. **AppArmor 支持：**
   - ubernetes 对 AppArmor 的支持已达到稳定版，用户可以通过在容器的 `securityContext` 中设置 `appArmorProfile.type` 字段来启用 AppArmor。
2. **改进的入站连接可靠性：**
   - ube-proxy 增强了对 `type: LoadBalancer` 和 `externalTrafficPolicy: Cluster` 服务的入站连接可靠性，减少了节点终止时的流量丢失。
3. **持久卷阶段转换时间：**
   - 入了 `PersistentVolumeStatus` 的 `lastTransitionTime` 字段，记录持久卷状态转换的时间戳，便于监控和调试。
4. **对 OCI 镜像卷的支持：**
   - 入了 Alpha 特性，允许在 Pod 中直接使用 OCI 镜像作为只读卷，简化了 AI/ML 工作流中的数据访问。
5. **nftables 后端：**
   - ube-proxy 的 nftables 后端晋级为 Beta，提供了比 iptables 更好的性能和可扩展性。
6. **弃用和移除：**
   -  cgroup v1 的支持转为维护模式，建议用户迁移到 cgroup v2。   - 除了 CephFS 和 Ceph RBD 树内卷插件，用户应迁移到相应的 CSI 驱动程序。   - 用了节点的 `status.nodeInfo.kubeProxyVersion` 字段，并将在未来版本中移除。
多详细信息，请参阅官方发布公告。
---
