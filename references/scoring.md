# 判别与评分参考

本表是 **1.0.0 版启发式验证优先级规则**，不是 OWASP 官方分数、漏洞严重度或漏洞概率。适用于本轮声明的资产单元、采集时间和网络视角；不能把内网扫描结果描述成互联网暴露。

## 1. 资产类型：线索如何变为标签

| 类型标签 | 召回线索 | 升为 observed/documented 所需依据与注意事项 |
| --- | --- | --- |
| main/core | `www/main/pay/order/sso`、品牌名、交易/身份 Title | 正常页面功能、业务方资料或明确依赖；`www` 不证明核心，SSO 字样不证明集团身份枢纽 |
| test/dev/uat/staging | `test-/dev-/qa-/uat-/pre-/staging-/sandbox-`、测试横幅 | 环境声明、部署资料或可适用的功能说明；命名不证明隔离、低影响或防御薄弱 |
| legacy/zombie | `old-/bak-/legacy-/v1-`、旧年份、过期证书 | 维护/退役记录、长期无维护的可信资料与当前可达证据；一张过期证书或旧版权年份不能证明僵尸系统 |
| outsourced/saas | 供应商页脚、SaaS CNAME、厂商登录/集成入口 | 官方租户/供应关系和实际业务数据流；供应商基础域不是客户可测试范围 |
| admin | `admin-/manage-/console-/ops-`、“管理/运维/监控” | 实际管理登录、菜单或适用文档；不由登录页推导弱口令或匿名管理权限 |
| api | `api-/gateway-`、JSON、OpenAPI/GraphQL 文档 | 实际响应、接口说明及对象/认证边界；JS 中一个路径不等于后端存在或免认证 |
| storage | 云存储域名、文件分发/附件/桶响应 | 提供者与资源/对象用途证据；静态公开资源可能符合预期，桶存在不等于误配置 |
| mobile-backend | `app-/mobile-/mapi-`、App 支持链接 | 用户提供的 App 网络记录、配置或官方接口资料；仅名称相似仍是推测 |
| partner/subsidiary | 联名入口、子品牌、合作方/子公司名称 | 项目范围、官方组织/主体关系和租户归属；同品牌/同备案只能提供关联，不能替代授权 |

SAN 中的名称用于关联候选，可能过期、共享或使用通配符，不证明仍存活、同环境或归同一企业。RFC1918 的 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 只说明私有地址空间，不证明测试环境或组织归属。每个 inferred 标签保留替代解释和待补依据。

## 2. 技术信号：能判定什么

| 线索 | 必须核对 | 可给出的结论/验证方向 |
| --- | --- | --- |
| 组件老旧、CVE/EOL | 供应商/产品、完整发行版/构建、来源时间、受影响版本范围、配置/认证/网络前提、发行版补丁回补 | 精确候选与适用前提；旧 Banner 不确认漏洞。EOL 是维护风险，不等于某个 CVE 可利用 |
| Redis 6379、MongoDB 27017、Elasticsearch 9200、RDP 3389 | 端口是否实际开放、协议/服务是否识别、观测视角、认证/ACL/网络策略状态 | 高价值服务复核候选。仅端口号不确认产品；服务可达不确认未授权。认证未知时建议核对，不尝试凭据 |
| Jenkins/GitLab 等研发管理系统 | 实际产品/管理面、访问上下文、公开内容是否预期 | 登录/公开项目仅说明入口；建议核对匿名权限、项目可见性和认证策略，不自动标“代码泄露” |
| 默认凭据/弱口令可能性 | 已识别产品、安装/初始配置状态、厂商策略、项目提供的认证资料 | 标 `CREDENTIAL_REVIEW`；仅类型最多弱线索，不报告概率或已存在弱口令。不附口令表、不自动尝试 |
| 调试/错误/配置线索 | 已有响应或可靠检测证据的真实内容、时间、匿名/登录状态；是否兜底页/示例 | 区分堆栈、phpinfo、敏感配置、凭据与普通错误页；`.git/.env` 命中需内容依据，HTTP 200 或路径名称不够。不为分类扩取敏感文件 |
| Swagger/OpenAPI/GraphQL | 文档与业务接口分离；schema/introspection、认证说明、字段敏感性与部署意图 | 文档可见或 introspection 开启不等于越权。建议核对信息暴露范围及接口认证，不能把所有文档定高危 |
| Druid 监控页 | **先分清 Alibaba Druid 连接池 StatViewServlet 与 Apache Druid 分析引擎**，再核对产品与访问内容 | 不能混用二者 CVE。监控入口可见不证明匿名敏感内容可读；建议核对登录、允许来源及信息范围 |
| 云存储/源站 | 资源归属、对象用途、读取/列举/写入各权限、策略与网络关联 | 公共静态资源可预期；公开桶名、云域名、IP 候选不确认误配置或 CDN 绕过。仅用最小已有脱敏证据，不批量下载、不试写 |

现代 Redis/Elasticsearch 可有默认保护/认证机制，不能把产品类型当作默认失守。CVSS 是漏洞严重度；EPSS 是 CVE 未来 30 天在野利用活动的预测；KEV 是已知被利用漏洞目录。三者均不能证明当前实例实际受影响，也不直接加入本表总分；有相关线索时再查当前官方数据并引用日期。

## 3. 四维离散档位

总上限为 `A20 + T40 + D20 + X20 = 100`。除 D 外同维只取最高适用档，不按条数叠加。业务后果 A、技术问题 T、独立防护问题 D 和广度 X 可以共同解释；同一缺陷不在 T/D 重复领取分值，没有额外“组合奖励”。

### A：类型与潜在业务影响（20）

| 分值 | 有证据的判别条件 |
| --- | --- |
| 0 | 低影响公开展示，或已确认隔离、全合成数据且无生产依赖的演示 |
| 5 | 已确认测试/UAT、遗留或外包应用，现有用途材料有限；影响仍可能更高时用区间，而非固定 5 |
| 10 | 明确支撑业务、管理/API/移动后端功能，影响范围有限 |
| 15 | 非公开客户/合同/财务数据、组织权限或重要系统集成 |
| 20 | 明确核心交易、核心身份、重要生产控制，或多个关键业务的依赖 |

仅有主站/测试/外包标签不能代替影响依据。环境、原业务重要性、维护状态继续单列，A 不是资产“是否归属核心”的判定。

### T：技术薄弱线索强度（40）

| 分值 | 判别条件 |
| --- | --- |
| 0 | 已检查声明观测面内的适用资料，未识别下列正向线索；不表示系统安全 |
| 5 | 实际观察到文档/登录、扫描记录的常见高风险端口或已识别产品的初始配置可能性等弱线索；域名关键词本身不够 |
| 10 | 已识别并可达的数据库/运维服务，认证待核对；可信 EOL；实际调试/堆栈等弱配置线索 |
| 20 | 产品/版本与厂商受影响范围吻合，但部署配置、补丁回补或其他前提未知；可信的具体发现候选 |
| 30 | 产品、版本、部署配置及访问前提都有依据支持适用性，尚未验证控制失效 |
| 40 | 同一实例已有可靠、适用当前状态的**授权验证证据**；保留原验证范围、来源、时间与问题影响 |

HTTP 200、文档页、某系统常见默认口令或历史 Banner 均不够 T40。T20/T30 本来就是未验证档位，不要求在本 Skill 内执行利用。若未检查的其他组件/资料可能改变现有最高档，使用区间；仅“尚未验证漏洞”不自动把一个已可判定的 T20 改成 T40 或所有维度未知。

### D：独立防护缺口（20）

四类各最多 5 分。每类记录 `gap / assessed_no_gap / not_applicable / counted_in_T / unknown` 与依据：gap 为 `[5,5]`；已检查无本类问题、确有理由的不适用或同缺陷已计 T 为 `[0,0]`；unknown 为 `[0,5]`。四类区间相加得到 D，不能把未知算缺失防护或算健康。

1. **WAF/边缘防护覆盖**：只有项目配置、权威覆盖资料等明确支持本应覆盖而未覆盖，才 gap。未识别 WAF 是 unknown；CDN detected 不等于 WAF detected。纯数据库协议不机械套用 Web WAF 要求。
2. **TLS**：实测弱协议/套件，或不符合预期客户端信任/有效期/主机名要求的证书问题，合计仍只算一类。自签在私有 PKI 中可能符合预期；TLS1.3 一次协商不证明旧协议已禁用，证书外观不证明弱套件。
3. **适用 HTTP 安全头**：按实际 HTML/API、嵌入需求和替代控制判断。缺多个头仍只算一类；CSP frame-ancestors 等有效替代不能忽略。不要求 JSON 接口具备所有 HTML 专用头，不把过时的头当加固指标。
4. **云/源站配置**：有证据的资源权限或源站访问边界缺口。公共桶/源站候选不够；若同一误配置已计 T，则本类记 counted_in_T，不重复。

例如只明确无 WAF，另外三类未查，D=`[5,20]`，不能写固定 5。WAF 有覆盖可支持该类 0，但不从 T 扣分，也不能宣称 WAF 防住了已有问题。

### X：暴露面广度（20）

| 同一授权观测面内的独立服务/应用入口单元数 | 分值 |
| --- | --- |
| 0–1 | 0 |
| 2 | 5 |
| 3–4 | 10 |
| 5–7 | 15 |
| ≥8 | 20 |

保留原始开放端口数和已识别服务数。相同应用的 HTTP/HTTPS、别名、重复扫描记录不重复计；同 IP 的不同租户/资产不能无依据聚合。独立认证/业务/部署单元可以分计，不能把几十个 URL 当几十个应用。扫描或识别覆盖不清时给 X 区间；例如至少发现 3 个单元但其余未识别，X=`[10,20]`。只有来源明确为外部视角才称互联网暴露。

## 4. 不完整信息、总分与阈值

本表 `[min,max]` 是区间的数学记法；传入脚本时使用整数、null 或 `{"min":值,"max":值}`，不使用 JSON 数组。

- 确定档位为整数或 `[v,v]`；全未知为 `null`，计算区间 `[0,该维上限]`；部分未知用有证据的 `{min,max}`。上下界均须来自该维离散档位。
- `L=Σmin`，`U=Σmax`。未知维度的 0 只是下界运算，不是填入实际零分。只有 `L=U` 才输出精确 `score_total`，否则精确总分为 null，展示区间。
- `coverage_percent = Σ(上下界相同维度的上限权重)`，总权重恰好为 100。部分已知维度仍不算确定覆盖；这是**判档覆盖率**，不是资料全覆盖、资产安全置信度或漏洞置信度。
- 区间仅描述本轮资料缺失导致的判档不确定性，不是潜在所有漏洞的真实风险边界。确定分值、100% 判档覆盖也不表示已完成渗透测试或已证明无隐藏问题；其他未评估字段仍保留。

严格按序，满足即停止：

| 规则 | 条件 | 结果 |
| --- | --- | --- |
| R0_SCOPE_EXCLUDED | 书面范围/用户明确排除，scope_status=out_of_scope | EXCLUDED，保留记录，停止目标补采与后续队列 |
| R1_T40_A15 | T.min=40 且 A.min≥15 | P1，已有严重业务影响证据，优先复核/处置，不被好防护抵消 |
| R2_L60_T20 | L≥60 且 T.min≥20 | P1 高优先级脆弱候选 |
| R3_L30_OR_T10 | 未满足上项，L≥30 或 T.min≥10 | P2 中优先级待验证 |
| R4_U30_C70_TX_EXACT | U<30、coverage≥70，且 T/X 上下界相同 | P3 低优先级常规 |
| R5_INSUFFICIENT | 其余 | P4 信息不足待补充 |

P1/P2 同时保留 missing_information；强线索不因其他缺字段丢失。scope_status=unknown 不改变有依据的优先级，但执行状态为待范围确认；归属疑问同样单列。主站无固定加分/减分，单独无 WAF、证书问题或安全头缺失不能越过技术门槛进入 P1。

同级优先考虑：适用当前实例的强技术证据 → 潜在后果 → 独立薄弱点叠加 → 证据时效/质量 → 下一步信息增益和成本。不得以端口多、名称可疑或防护指纹缺失压过已有严重问题证据。

### 计算算例

下列固定分值均假设判档所需材料在声明观测面内已充分检查；不是从“没给字段”推得 0。

| 资产/证据情形 | A | T | D | X | L–U / 等级 |
| --- | --- | --- | --- | --- | --- |
| 低影响展示站，有三类防护卫生问题 | 0 | 0 | 15 | 0 | 15–15 / P3；卫生问题不等于高危漏洞 |
| 已确认 UAT 支撑业务，具体 CVE 候选、三类防护缺口、五个独立服务 | 10 | 20 | 15 | 15 | 60–60 / P1；可高于主站 |
| 仅 Jenkins 登录页，其他技术/业务未核实 | [0,20] | [5,40] | [0,20] | 0 | 5–80 / P4；不能声称默认口令 |
| 非公开业务数据存在已有授权证实的严重访问控制问题，防护较好 | 15 | 40 | 0 | 0 | 55–55 / P1；R1 硬升级 |
| 只有 dev-admin 域名，无其他资料 | null | null | null | null | 0–100 / P4；名称不计分 |
| 同实例有 T30 适用性资料，其他三维未知 | null | 30 | null | null | 30–90 / P2，同时待补充 |

## 5. 计算脚本的数据契约

`score_assets.py` 输入是资产对象数组，保留任意业务字段。每项 `asset_id` 为非空唯一字符串；`scores` 只允许 A/T/D/X；`evidence_refs` 为维度到证据 ID 数组的映射。任何不是全未知 `[0,上限]` 的分值/区间均需非空引用，确定 0 也需要；脚本只检查引用结构，不验证证据真实性，Agent 仍需核对旁表与事实。脚本不是脱敏器，传入前应去除凭据、敏感参数及不必要的响应明细。

`scope_status` 允许 in_scope/unknown/out_of_scope，缺省 unknown；`enrichment_mode` 允许 offline/authorized_read_only/unspecified，缺省 unspecified，由 Agent 根据本轮已有约束写入。模式不改变分数，执行状态依次为：超范围 excluded；范围未知 hold_scope_confirmation；范围内离线 offline_analysis_only；范围内获准只读补采 read_only_enrichment_allowed；范围内未指定动作权限 review_plan_only。任何模式均不授权本 Skill 开展漏洞利用或自动启动扫描。

```json
[
  {
    "asset_id": "A01",
    "scope_status": "in_scope",
    "scores": {"A": 10, "T": 20, "D": {"min": 5, "max": 20}, "X": 15},
    "evidence_refs": {"A": ["E1"], "T": ["E2"], "D": ["E3"], "X": ["E4"]}
  }
]
```

此例 L=50、U=65，确定覆盖为 A20+T40+X20=80%，P2；不能因最高可能 65 就直接判 P1。输入 bool、非法分值/区间、重复 ID 或有分无引用会整批报错，不发布半份结果。修复问题后重试，不能删除异常行凑出完整报告。script 输出根对象含 `scoring_version/summary/assets`，每项增加 `triage`；实际键名以脚本为准。

## 6. 依据与查询入口（只在相关时查）

- [OWASP 攻击面分析](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)：按入口、功能与数据组织评估。
- [Redis 安全模型](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)、[MongoDB 安全检查表](https://www.mongodb.com/docs/manual/administration/security-checklist/)、[Elasticsearch 安全自动配置](https://www.elastic.co/docs/deploy-manage/security/self-auto-setup)、[Microsoft RDS 端口](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/ports-used-by-rds)：暴露不等于未授权。
- [OpenAPI 认证](https://swagger.io/docs/specification/v3_0/authentication/)、[GraphQL 安全](https://www.graphql.org/learn/security/)、[Alibaba Druid 监控配置](https://github.com/alibaba/druid/wiki/%E9%85%8D%E7%BD%AE_StatViewServlet%E9%85%8D%E7%BD%AE)、[GitLab 可见性](https://docs.gitlab.com/user/public_access/)：区分文档/产品入口与访问控制。
- [Red Hat 补丁回补](https://access.redhat.com/security/updates/backporting)、[FIRST CVSS](https://www.first.org/cvss/v4.0/user-guide)、[FIRST EPSS](https://www.first.org/epss/faq)、[CISA KEV 官方数据](https://github.com/cisagov/kev-data)：核对实例适用性，不机械按上游版本或指标定风险。
- [Cloudflare Proxy status](https://developers.cloudflare.com/dns/proxy-status/)、[OWASP HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)、[OWASP TLS](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)、[AWS S3 公共访问](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)：防护与配置需具体证据。
- [RFC1918](https://www.rfc-editor.org/rfc/rfc1918.html)、[域名控制验证](https://letsencrypt.org/how-it-works/)：地址/证书关联与组织归属不同。
