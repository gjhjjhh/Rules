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

# 路径配置
BASE_DIR = Path(__file__).resolve().parent  # 库主目录
DOMAIN_DIR = BASE_DIR / "domain"  # main.py生成的域名目录
OUTPUT_ROOT = BASE_DIR / "output"  # 输出目录

# 格式配置（严格按参考示例）
FORMAT_CONFIG = {
    "singbox": {
        "suffix": ".json",
        "comment": "//",
        "title": "Singbox 规则集",
        "desc": "适用于Singbox v3",
        "convert": lambda domains: {
            "version": 3,
            "rules": [{"domain_suffix": domains}]
        }
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
        "convert": lambda domains: [
            "127.0.0.1\tlocalhost",
            "0.0.0.0\t0.0.0.0",
            ""] + [f"0.0.0.0\t{d}" for d in domains]
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
    """获取元数据（简化版）"""
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC+8"),
        "repo": "https://github.com/gjhjjhh/Rules"
    }


def read_domains(file_path):
    """读取域名（不进行任何处理）"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"⚠️ 读取文件错误: {file_path} - {str(e)}")
        return []


def build_header(fmt_info, total, meta):
    """生成文件头（简化版）"""
    comment = fmt_info["comment"]
    if fmt_info.get("special_header"):  # Loon格式特殊头部
        return [
            f"#!name={fmt_info['title']}",
            f"#!desc={fmt_info['desc']}",
            f"#!date={meta['time']}",
            f"#!homepage={meta['repo']}",
            ""
        ]
    else:  # 通用头部
        return [
            f"{comment} Title: {fmt_info['title']}",
            f"{comment} Description: {fmt_info['desc']}",
            f"{comment} Time: {meta['time']}",
            f"{comment} Homepage: {meta['repo']}",
            f"{comment}",
            ""
        ]


def process_file(file_path, meta):
    """处理单个域名文件"""
    rule_name = file_path.stem
    domains = read_domains(file_path)
    
    # 创建输出目录
    out_dir = OUTPUT_ROOT / rule_name
    out_dir.mkdir(exist_ok=True)
    print(f"\n处理规则：{rule_name}（域名数：{len(domains)}）")

    for fmt_name, fmt in FORMAT_CONFIG.items():
        # 生成输出文件路径
        output_file = out_dir / f"{fmt_name}{fmt['suffix']}"
        
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                # 写入文件头
                header = build_header(fmt, len(domains), meta)
                f.write("\n".join(header))
                
                # 写入规则内容
                if fmt_name == "singbox":
                    # Singbox使用JSON格式
                    rules = fmt["convert"](domains)
                    json.dump(rules, f, indent=2, ensure_ascii=False)
                else:
                    # 其他格式直接写入文本行
                    rules = fmt["convert"](domains)
                    f.write("\n".join(rules))
            
            print(f"✓ 生成: {output_file.relative_to(BASE_DIR)}")
        except Exception as e:
            print(f"⚠️ 生成文件错误: {output_file} - {str(e)}")


def main():
    print("="*50)
    print("域名规则格式转换工具")
    print("="*50)
    
    # 获取元数据
    meta = get_meta()
    print(f"开始时间: {meta['time']}")
    print(f"仓库地址: {meta['repo']}")
    
    # 确保domain目录存在
    if not DOMAIN_DIR.exists():
        print(f"⚠️ 错误: 目录不存在 - {DOMAIN_DIR}")
        return
    
    # 处理domain目录下的所有txt文件
    processed = 0
    for file in DOMAIN_DIR.glob("*.txt"):
        if file.is_file():
            process_file(file, meta)
            processed += 1
    
    print("\n" + "="*50)
    print(f"处理完成! 共处理 {processed} 个规则文件")
    print(f"输出目录: {OUTPUT_ROOT.relative_to(BASE_DIR)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n操作已取消")
    except Exception as e:
        print(f"严重错误: {str(e)}")
