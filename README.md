# loon-cn-rules

给 Loon 用的国内直连分流规则，每天北京时间 06:00 由 GitHub Actions 自动从上游拉取、合并、去重后生成。

## 规则文件

| 文件 | 内容 |
|---|---|
| `dist/CN_Domain.list` | 国内域名（DOMAIN-SUFFIX / DOMAIN），约 11 万条 |
| `dist/CN_IP.list` | 国内 IP 段（IP-CIDR / IP-CIDR6），全部带 `no-resolve` |

上游来源：

- [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) `direct-list.txt`
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) `ChinaMaxNoMedia_Domain.list`
- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) `text/cn.txt`

## Loon 配置示例

目标是不让本地 DNS 解析不认识的域名，从而避免 DNS 泄露：国内流量只靠域名列表识别，不使用 `GEOIP,cn`。

Loon 的匹配顺序是：域名类规则都没命中时，才解析 DNS 去匹配 IP 类规则。所以**配置里所有 IP 规则（包括别人的规则集，例如 Telegram 的 IP 段）都必须带 `no-resolve`**，只要有一条不带，未命中的境外域名就仍会在本地被解析。

```ini
[General]
dns-server = 223.5.5.5, 119.29.29.29

[Remote Rule]
https://raw.githubusercontent.com/kk66615/loon-cn-rules/main/dist/CN_Domain.list, policy=DIRECT, tag=CN_Domain, enabled=true
https://raw.githubusercontent.com/kk66615/loon-cn-rules/main/dist/CN_IP.list, policy=DIRECT, tag=CN_IP, enabled=true

[Rule]
# 不要加 GEOIP,cn,DIRECT：它会让未匹配的境外域名先在本地用国内 DNS 解析
# PROXY 换成你自己的代理策略组名
FINAL,PROXY
```

规则优先级：本地 `[Rule]` > 插件规则 > `[Remote Rule]`。想让某个被本列表直连的域名走代理，在 `[Rule]` 里写一条 `DOMAIN-SUFFIX,example.cn,PROXY` 即可。

`raw.githubusercontent.com` 打不开时，换成 jsDelivr：

```
https://cdn.jsdelivr.net/gh/kk66615/loon-cn-rules@main/dist/CN_Domain.list
https://cdn.jsdelivr.net/gh/kk66615/loon-cn-rules@main/dist/CN_IP.list
```

代价：不在列表里的国内域名会走代理。遇到这种情况，把域名加进 `custom/direct.list`。

## 自定义

- `custom/direct.list`：额外直连的域名或规则，写法见文件内注释。
- `custom/exclude.list`：从上游剔除的域名（连同子域名）。

推送到 `main` 后会自动重新构建。

## 本地构建

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build.py
```

以下情况构建会失败，不会覆盖已发布的规则：任一上游域名源少于 9 万条、IP 源少于 8000 条、上游不再包含 qq.com / taobao.com / dingtalk.com 等关键域名、`custom/` 里有格式错误的行。
