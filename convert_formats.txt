#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
域名规则格式转换工具
输出路径：主目录/output/[规则名称]/[格式文件]
"""
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

# 路径配置（默认脚本在主目录，domain目录由main.py生成）
BASE_DIR = Path(__file__).resolve().parent  # 库主目录
DOMAIN_DIR = BASE_DIR / "domain"  # main.py生成的域名目录
OUTPUT_ROOT = BASE_DIR / "output"  # 输出目录

# 格式配置（保留所有格式）
FORMAT_CONFIG = {
    "singbox": {
        "suffix": ".json",
        "comment": "//",
        "title": "Singbox 规则集",
        "desc": "适用于Singbox v3",
        "convert": lambda domains: {"version": 3, "rules": [{"domain_suffix": domains}]}
    },
    "adblock": {
        "suffix": ".txt",
        "comment": "!",
        "title": "Adblock 规则",
        "desc": "通用Adblock协议",
        "convert": lambda domains: [f"||{d}^" for d in domains]
    },
    "adguard": {
        "suffix": ".txt",
        "comment": "!",
        "title": "AdGuardHome 规则",
        "desc": "适用于AdGuard",
        "convert": lambda domains: [f"||{d}^" for d in domains]
    },
    "dnsmasq": {
        "suffix": ".conf",
        "comment": "#",
        "title": "DNSMasq 规则",
        "desc": "适用于DNSMasq",
        "convert": lambda domains: [f"local=/{d}/" for d in domains]
    },
    "hosts": {
        "suffix": ".txt",
        "comment": "#",
        "title": "Hosts 规则",
        "desc": "系统Hosts文件",
        "convert": lambda domains: ["127.0.0.1\tlocalhost", "0.0.0.0\t0.0.0.0", ""] + [f"0.0.0.0\t{d}" for d in domains]
    },
    "quantumultx": {
        "suffix": ".list",
        "comment": "#",
        "title": "QuantumultX 规则",
        "desc": "适用于QuantumultX",
        "convert": lambda domains: [f"host-suffix,{d},reject" for d in domains]
    },
    "loon": {
        "suffix": ".list",
        "comment": "#",
        "title": "Loon 规则",
        "desc": "适用于Loon",
        "convert": lambda domains: [f"DOMAIN-SUFFIX,{d}" for d in domains],
        "special_header": True
    },
    "mihomo": {
        "suffix": ".yaml",
        "comment": "#",
        "title": "Mihomo 规则",
        "desc": "适用于Clash Meta",
        "convert": lambda domains: ["payload:"] + [f"  - '+.{d}'" for d in domains]
    }
}

# 初始化输出目录
OUTPUT_ROOT.mkdir(exist_ok=True)


def get_meta():
    """获取元数据"""
    try:
        version = subprocess.check_output(
            ["git", "describe", "--abbrev=0", "--tags"],
            stderr=subprocess.STDOUT,
            cwd=BASE_DIR
        ).strip().decode() or "unknown"
    except:
        version = "unknown"
    return {
        "version": version,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC+8"),
        "repo": "https://github.com/your-repo"
    }


def read_domains(file_path):
    """读取域名（去重）"""
    with open(file_path, "r", encoding="utf-8") as f:
        return list(set([line.strip() for line in f if line.strip()]))


def build_header(fmt_info, total, meta):
    """生成文件头"""
    comment = fmt_info["comment"]
    header = []
    if fmt_info.get("special_header"):
        header = [
            f"#!name={fmt_info['title']}",
            f"#!desc={fmt_info['desc']} | 版本：{meta['version']}",
            f"#!date={meta['time']}",
            f"#!homepage={meta['repo']}",
            ""
        ]
    else:
        header = [
            f"{comment}{fmt_info['title']}",
            f"{comment}描述：{fmt_info['desc']}",
            f"{comment}版本：{meta['version']} | 更新时间：{meta['time']}",
            f"{comment}来源：{meta['repo']}",
            f"{comment}",
            ""
        ]
    return header


def process_file(file_path, meta):
    """处理单个域名文件"""
    rule_name = file_path.stem
    domains = read_domains(file_path)
    if not domains:
        print(f"⚠️ 跳过空文件：{rule_name}")
        return

    out_dir = OUTPUT_ROOT / rule_name
    out_dir.mkdir(exist_ok=True)
    print(f"\n处理规则：{rule_name}（域名数：{len(domains)}）")

    for fmt_name, fmt in FORMAT_CONFIG.items():
        rules = fmt["convert"](domains)
        total = len(rules["rules"][0]["domain_suffix"]) if fmt_name == "singbox" else len(rules)
        output_file = out_dir / f"{fmt_name}{fmt['suffix']}"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(build_header(fmt, total, meta)))
            if fmt_name == "singbox":
                json.dump(rules, f, indent=2, ensure_ascii=False)
            else:
                f.write("\n".join(rules))
        print(f"生成：{output_file.relative_to(BASE_DIR)}")


def main():
    meta = get_meta()
    # 直接处理domain目录下的txt文件（默认存在）
    for file in DOMAIN_DIR.glob("*.txt"):
        if file.is_file():
            process_file(file, meta)
    print(f"\n完成，输出目录：{OUTPUT_ROOT.relative_to(BASE_DIR)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断")
