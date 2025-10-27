#!/usr/bin/env python3
import os
import sys
import argparse
import fnmatch

DEFAULT_IGNORES = [
    ".DS_Store"
]

def should_ignore(rel_path, name, ignore_patterns):
    # 同时对“文件名本身”和“相对路径”做匹配，更灵活
    for pat in ignore_patterns:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_path, pat):
            return True
    return False

def list_all_files(root_dir, ignore_patterns):
    """递归列出 root_dir 下所有文件（不含文件夹），返回绝对路径列表；支持忽略模式。"""
    results = []
    root_dir = os.path.abspath(root_dir)

    def onerror(err):
        print(f"[WARN] 无法访问: {err.filename}", file=sys.stderr)

    for current_root, _, files in os.walk(root_dir, topdown=True, onerror=onerror, followlinks=False):
        base_rel = os.path.relpath(current_root, root_dir)
        for name in files:
            rel_path = os.path.normpath(os.path.join(base_rel, name)) if base_rel != "." else name
            if should_ignore(rel_path, name, ignore_patterns):
                continue
            results.append(os.path.join(current_root, name))
    return results

def main():
    parser = argparse.ArgumentParser(
        description="递归列出指定目录及其子目录中的所有文件（不包含文件夹），支持忽略模式。"
    )
    parser.add_argument("directory", help="要扫描的目录路径")
    parser.add_argument(
        "--relative", "-r", action="store_true",
        help="以相对路径输出（相对于输入目录）。默认输出绝对路径。"
    )
    parser.add_argument(
        "--ignore", "-i", action="append", default=[],
        help="追加忽略模式（可多次使用），如：-i '*.log' -i 'build/*'"
    )
    parser.add_argument(
        "--out", "-o", metavar="FILE",
        help="将结果写入到指定文件（UTF-8），同时仍会在终端打印数量统计。"
    )
    args = parser.parse_args()

    if not os.path.exists(args.directory):
        print(f"[ERROR] 路径不存在: {args.directory}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(args.directory):
        print(f"[ERROR] 不是目录: {args.directory}", file=sys.stderr)
        sys.exit(1)

    ignore_patterns = DEFAULT_IGNORES + args.ignore

    files = list_all_files(args.directory, ignore_patterns)

    files_to_print = (
        [os.path.relpath(p, os.path.abspath(args.directory)) for p in files]
        if args.relative else files
    )

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write("\n".join(files_to_print))
        except OSError as e:
            print(f"[ERROR] 写文件失败: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"在目录 '{args.directory}' 下找到 {len(files_to_print)} 个文件（已应用忽略：{ignore_patterns}）。")
    for p in files_to_print:
        print(p)

if __name__ == "__main__":
    main()
