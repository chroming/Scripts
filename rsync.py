#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import logging
import os
import shutil
import sys
import time
import json
import subprocess
from pathlib import Path
from typing import Iterable, Iterator, Tuple, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

CHUNK_SIZE = 1024 * 1024  # 1 MiB
VIDEO_EXTS = {".mp4", ".m4v", ".mov", ".mkv", ".avi", ".flv", ".ts", ".m2ts", ".wmv", ".webm"}

# ---------------- Logging ----------------

def setup_logging(verbose: bool):
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
        datefmt="%H:%M:%S"
    )

# ---------------- Args ----------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Move/copy SRC -> DST, rsync-like merge with safe delete. "
                    "Fast paths: name+size trust, ffprobe video signature, adaptive sampled hashing."
    )
    p.add_argument("src", help="Source directory")
    p.add_argument("dst", help="Destination directory")

    # semantics
    p.add_argument("--delete-source", action="store_true",
                   help="After success (copy OR identical-skip), delete source files and prune empty dirs.")
    p.add_argument("--keep-source-root", action="store_true",
                   help="When pruning empty dirs under SRC, keep SRC root directory (do not remove it).")
    p.add_argument("--fsync-before-delete", action="store_true",
                   help="fsync the destination file before deleting the source (safer across disks/power loss; slower).")

    # ultra-fast label equality
    p.add_argument("--trust-name-size", action="store_true",
                   help="If destination has same relative path (same name) AND same size, treat as identical without any hashing (fastest, small risk).")

    # hashing
    p.add_argument("--algo", default="auto", choices=["auto", "blake3", "blake2b", "sha256", "md5"],
                   help="Hash algorithm. 'auto' prefers blake3, else blake2b, else sha256.")
    p.add_argument("--quick-bytes", type=int, default=4 * 1024 * 1024,
                   help="Head quick-hash bytes before full-hash for small/medium files (0 to disable).")

    # big-file optimization (adaptive sampled hashing)
    p.add_argument("--big-threshold", type=int, default=512 * 1024 * 1024,
                   help="Size threshold (bytes) to use sampled-hash for big files. Default: 512 MiB.")
    p.add_argument("--sampled-chunk-size", type=int, default=8 * 1024 * 1024,
                   help="Each sample chunk size in bytes (default: 8 MiB).")
    p.add_argument("--samples-per-gib", type=int, default=6,
                   help="Adaptive sampled-hash: samples per GiB (default: 6).")
    p.add_argument("--max-sampled-bytes", type=int, default=64 * 1024 * 1024,
                   help="Adaptive sampled-hash: upper bound on total sampled bytes (default: 64 MiB).")
    p.add_argument("--trust-sampled", action="store_true",
                   help="If sampled-hash equals, treat as identical without full-hash (faster).")

    # video fast signature (ffprobe)
    p.add_argument("--use-video-signature", action="store_true",
                   help="Use ffprobe-based video signature as fastest equality check for common video types.")
    p.add_argument("--trust-video-signature", action="store_true",
                   help="If video signatures equal, treat as identical without further hashing.")

    # io & traversal
    p.add_argument("--ignore", action="append", default=[".DS_Store"],
                   help="Filename to ignore (can repeat). Default: .DS_Store")
    p.add_argument("--follow-symlinks", action="store_true",
                   help="Follow symlinks when copying. Default: copy link itself where possible.")
    p.add_argument("--dry-run", action="store_true", help="Plan only, do not copy/rename/delete.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logs (prints per-file [START] lines).")
    p.add_argument("--workers", type=int, default=max(4, (os.cpu_count() or 4) * 2),
                   help="Thread pool size for hashing/copying (I/O-bound).")
    p.add_argument("--max-copy", type=int, default=4,
                   help="Limit concurrent copy operations (avoid disk thrash).")
    return p.parse_args()

# ---------------- Hash helpers ----------------

def pick_hasher(algo: str):
    if algo == "blake3":
        try:
            import blake3
            return "blake3", (lambda: blake3.blake3())
        except Exception:
            logging.warning("blake3 not available, falling back to blake2b.")
            algo = "blake2b"
    if algo == "auto":
        try:
            import blake3
            return "blake3", (lambda: blake3.blake3())
        except Exception:
            return "blake2b", (lambda: hashlib.blake2b())
    if algo == "blake2b":
        return "blake2b", (lambda: hashlib.blake2b())
    if algo == "md5":
        return "md5", (lambda: hashlib.md5())
    return "sha256", (lambda: hashlib.sha256())

def file_quick_hash(path: Path, new_hasher, quick_bytes: int) -> Optional[str]:
    if quick_bytes <= 0:
        return None
    h = new_hasher()
    read_total = 0
    with path.open("rb") as f:
        while read_total < quick_bytes:
            need = min(CHUNK_SIZE, quick_bytes - read_total)
            buf = f.read(need)
            if not buf:
                break
            h.update(buf)
            read_total += len(buf)
    return h.hexdigest()

def file_full_hash(path: Path, new_hasher) -> str:
    h = new_hasher()
    with path.open("rb") as f:
        while True:
            buf = f.read(CHUNK_SIZE)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()

def file_sampled_hash_adaptive(path: Path, new_hasher, file_size: int,
                               chunk_size: int, samples_per_gib: int, max_total: int) -> str:
    h = new_hasher()
    if file_size <= chunk_size:
        with path.open("rb") as f:
            while True:
                buf = f.read(CHUNK_SIZE)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()

    gib = (file_size + (1 << 30) - 1) // (1 << 30)
    num = max(3, samples_per_gib * max(1, gib))
    num = min(num, max(1, max_total // chunk_size))
    if num <= 1:
        num = 3

    with path.open("rb") as f:
        for i in range(num):
            t = i / (num - 1) if num > 1 else 0.0
            pos = int((file_size - chunk_size) * t)
            f.seek(pos, os.SEEK_SET)
            left = chunk_size
            while left > 0:
                buf = f.read(min(CHUNK_SIZE, left))
                if not buf:
                    break
                h.update(buf)
                left -= len(buf)
    return h.hexdigest()

# --------- Video fast signature (ffprobe) ----------

def ffprobe_signature(path: Path, new_hasher) -> Optional[str]:
    try:
        cmd = [
            "ffprobe", "-v", "quiet",
            "-select_streams", "v:a:s",
            "-count_frames", "-show_streams", "-show_format",
            "-of", "json", str(path)
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        data = json.loads(out.decode("utf-8", "ignore"))

        fmt = data.get("format", {})
        dur = fmt.get("duration")
        br  = fmt.get("bit_rate")
        size = fmt.get("size")
        start = fmt.get("start_time")
        tags = fmt.get("tags", {}) or {}
        tags.pop("encoder", None)

        streams = []
        for s in data.get("streams", []):
            keep = {
                "codec_type": s.get("codec_type"),
                "codec_name": s.get("codec_name"),
                "profile": s.get("profile"),
                "level": s.get("level"),
                "width": s.get("width"),
                "height": s.get("height"),
                "sample_rate": s.get("sample_rate"),
                "channels": s.get("channels"),
                "channel_layout": s.get("channel_layout"),
                "bit_rate": s.get("bit_rate"),
                "nb_frames": s.get("nb_frames") or s.get("nb_read_frames"),
                "avg_frame_rate": s.get("avg_frame_rate"),
                "r_frame_rate": s.get("r_frame_rate"),
                "tags": s.get("tags", {}) or {},
            }
            keep["tags"].pop("encoder", None)
            streams.append(keep)

        sig_obj = {
            "duration": dur, "bit_rate": br, "size": size, "start_time": start,
            "format_tags": tags, "streams": streams
        }
        sig_json = json.dumps(sig_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        h = new_hasher()
        h.update(sig_json)
        return h.hexdigest()
    except Exception:
        return None

# ---------------- FS helpers ----------------

def is_ignored(name: str, ignore_list: Iterable[str]) -> bool:
    return name in ignore_list

def ensure_dir(path: Path, dry_run: bool):
    if dry_run:
        return
    path.mkdir(parents=True, exist_ok=True)

def conflict_name(dst_file: Path) -> Path:
    stem, suf = dst_file.stem, dst_file.suffix
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    candidate = dst_file.with_name(f"{stem}__conflict_{timestamp}{suf}")
    if not candidate.exists():
        return candidate
    n = 2
    while True:
        c = dst_file.with_name(f"{stem}__conflict_{timestamp}_{n}{suf}")
        if not c.exists():
            return c
        n += 1

def copy_file(src_file: Path, dst_file: Path, follow_symlinks: bool, dry_run: bool, copy_sem: threading.Semaphore):
    if dry_run:
        logging.info(f"[DRY] COPY {src_file} -> {dst_file}")
        return
    ensure_dir(dst_file.parent, dry_run=False)
    with copy_sem:
        shutil.copy2(src_file, dst_file, follow_symlinks=follow_symlinks)

def fsync_file(path: Path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def delete_file(path: Path, dry_run: bool) -> bool:
    if dry_run:
        logging.info(f"[DRY] DELETE {path}")
        return False  # not actually deleted
    try:
        path.unlink()
        return True
    except Exception as e:
        logging.warning(f"Failed to delete source {path}: {e}")
        return False

def _rscandir(root: Path, topdown: bool = True) -> Iterator[os.DirEntry]:
    if topdown:
        for e in os.scandir(root):
            yield e
            if e.is_dir(follow_symlinks=False):
                yield from _rscandir(Path(e.path), topdown=topdown)
    else:
        for e in os.scandir(root):
            if e.is_dir(follow_symlinks=False):
                yield from _rscandir(Path(e.path), topdown=topdown)
        for e in os.scandir(root):
            yield e

def walk_files(src_root: Path, ignore_list: Iterable[str]) -> Iterator[Tuple[Path, Path]]:
    for e in _rscandir(src_root, topdown=True):
        name = e.name
        if is_ignored(name, ignore_list):
            continue
        try:
            if e.is_file(follow_symlinks=False) or (e.is_symlink() and Path(e.path).is_file()):
                abs_p = Path(e.path)
                rel = abs_p.relative_to(src_root)
                yield abs_p, rel
        except Exception as ex:
            logging.warning(f"Walk skip {e.path}: {ex}")

# ---------------- Thread-safe counters & lists ----------------

COUNTER_LOCK = threading.Lock()
LIST_LOCK = threading.Lock()

def inc(counters: dict, key: str, n: int = 1):
    with COUNTER_LOCK:
        counters[key] = counters.get(key, 0) + n

def add_failed(lst: List[str], path: str):
    with LIST_LOCK:
        lst.append(path)

# ---------------- Safe deletion with TOCTOU guard ----------------

def safe_delete_if_unchanged(src_file: Path, snap: os.stat_result, dry_run: bool) -> bool:
    try:
        now = src_file.stat()
    except Exception as e:
        logging.warning(f"Stat before delete failed {src_file}: {e}")
        return False
    if now.st_size != snap.st_size or int(now.st_mtime) != int(snap.st_mtime):
        logging.warning(f"Skip delete (changed after hash/label): {src_file}")
        return False
    return delete_file(src_file, dry_run)

# ---------------- Core per-file ----------------

def handle_one_file(
    src_file: Path, rel_path: Path, dst_root: Path,
    quick_bytes: int, big_threshold: int,
    sampled_chunk_size: int, samples_per_gib: int, max_sampled_bytes: int,
    use_video_signature: bool, trust_video_signature: bool, trust_sampled: bool, trust_name_size: bool,
    new_hasher, follow_symlinks: bool,
    delete_source: bool, fsync_before_delete: bool, dry_run: bool, copy_sem: threading.Semaphore,
    counters: dict, failed_files: List[str]
):
    dst_file = dst_root / rel_path
    try:
        # early snapshot for safe delete
        try:
            src_stat = src_file.stat()
        except Exception as e:
            logging.warning(f"Stat failed (src) {src_file}: {e}")
            inc(counters, "errors")
            add_failed(failed_files, str(src_file))
            return

        logging.info(f"[START] {rel_path} | size={src_stat.st_size} | src={src_file} | dst={dst_file}")

        if not dst_file.exists():
            copy_file(src_file, dst_file, follow_symlinks, dry_run, copy_sem)
            if fsync_before_delete and not dry_run:
                try:
                    fsync_file(dst_file)
                except Exception as e:
                    logging.warning(f"fsync failed for {dst_file}: {e}")
                    inc(counters, "errors")
            inc(counters, "copied")
            if delete_source:
                if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                    inc(counters, "deleted")
            return

        # target exists: compare size first
        try:
            dst_stat = dst_file.stat()
        except Exception as e:
            logging.warning(f"Stat failed (dst) {dst_file}: {e}")
            inc(counters, "errors")
            add_failed(failed_files, str(src_file))
            return

        if src_stat.st_size != dst_stat.st_size:
            new_name = conflict_name(dst_file)
            copy_file(src_file, new_name, follow_symlinks, dry_run, copy_sem)
            if fsync_before_delete and not dry_run:
                try:
                    fsync_file(new_name)
                except Exception as e:
                    logging.warning(f"fsync failed for {new_name}: {e}")
                    inc(counters, "errors")
            inc(counters, "renamed_conflicts")
            if delete_source:
                if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                    inc(counters, "deleted")
            return

        # ===== Ultra-fast path: trust name + size =====
        if trust_name_size:
            # 相对路径同名已成立（rel_path 一致），size 也相等 -> 直接判相同
            logging.info(f"[FAST-NAME-SIZE] Treat as identical (no hashing): {rel_path}")
            inc(counters, "skipped_identical")
            if delete_source:
                if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                    inc(counters, "deleted")
            return

        # same size: video fast signature (if enabled & video-like)
        if use_video_signature and src_file.suffix.lower() in VIDEO_EXTS:
            sig_s = ffprobe_signature(src_file, new_hasher)
            sig_d = ffprobe_signature(dst_file, new_hasher)
            if sig_s and sig_d and sig_s == sig_d:
                inc(counters, "skipped_identical")
                if delete_source:
                    if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                        inc(counters, "deleted")
                return

        # big files: adaptive sampled hashing (bounded I/O)
        if src_stat.st_size >= big_threshold:
            try:
                s_samp = file_sampled_hash_adaptive(
                    src_file, new_hasher, src_stat.st_size,
                    sampled_chunk_size, samples_per_gib, max_sampled_bytes
                )
                d_samp = file_sampled_hash_adaptive(
                    dst_file, new_hasher, dst_stat.st_size,
                    sampled_chunk_size, samples_per_gib, max_sampled_bytes
                )
            except Exception as e:
                logging.warning(f"Sampled-hash failed {src_file} or {dst_file}: {e}")
                inc(counters, "errors")
                add_failed(failed_files, str(src_file))
                return

            if s_samp != d_samp:
                new_name = conflict_name(dst_file)
                copy_file(src_file, new_name, follow_symlinks, dry_run, copy_sem)
                if fsync_before_delete and not dry_run:
                    try:
                        fsync_file(new_name)
                    except Exception as e:
                        logging.warning(f"fsync failed for {new_name}: {e}")
                        inc(counters, "errors")
                inc(counters, "renamed_conflicts")
                if delete_source:
                    if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                        inc(counters, "deleted")
                return

            if trust_sampled or (trust_video_signature and use_video_signature):
                inc(counters, "skipped_identical")
                if delete_source:
                    if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                        inc(counters, "deleted")
                return

            # fallback to full hash to confirm (safer; slower)
            try:
                s_full = file_full_hash(src_file, new_hasher)
                d_full = file_full_hash(dst_file, new_hasher)
            except Exception as e:
                logging.warning(f"Full-hash failed {src_file} or {dst_file}: {e}")
                inc(counters, "errors")
                add_failed(failed_files, str(src_file))
                return

            if s_full == d_full:
                inc(counters, "skipped_identical")
                if delete_source:
                    if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                        inc(counters, "deleted")
            else:
                new_name = conflict_name(dst_file)
                copy_file(src_file, new_name, follow_symlinks, dry_run, copy_sem)
                if fsync_before_delete and not dry_run:
                    try:
                        fsync_file(new_name)
                    except Exception as e:
                        logging.warning(f"fsync failed for {new_name}: {e}")
                        inc(counters, "errors")
                inc(counters, "renamed_conflicts")
                if delete_source:
                    if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                        inc(counters, "deleted")
            return

        # small/medium files: head quick-hash → full-hash
        if quick_bytes > 0:
            try:
                s_q = file_quick_hash(src_file, new_hasher, quick_bytes)
                d_q = file_quick_hash(dst_file, new_hasher, quick_bytes)
            except Exception as e:
                logging.warning(f"Quick-hash failed {src_file} or {dst_file}: {e}")
                inc(counters, "errors")
                add_failed(failed_files, str(src_file))
                return
            if s_q is not None and d_q is not None and s_q != d_q:
                new_name = conflict_name(dst_file)
                copy_file(src_file, new_name, follow_symlinks, dry_run, copy_sem)
                if fsync_before_delete and not dry_run:
                    try:
                        fsync_file(new_name)
                    except Exception as e:
                        logging.warning(f"fsync failed for {new_name}: {e}")
                        inc(counters, "errors")
                inc(counters, "renamed_conflicts")
                if delete_source:
                    if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                        inc(counters, "deleted")
                return

        try:
            s_h = file_full_hash(src_file, new_hasher)
            d_h = file_full_hash(dst_file, new_hasher)
        except Exception as e:
            logging.warning(f"Full-hash failed {src_file} or {dst_file}: {e}")
            inc(counters, "errors")
            add_failed(failed_files, str(src_file))
            return

        if s_h == d_h:
            inc(counters, "skipped_identical")
            if delete_source:
                if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                    inc(counters, "deleted")
        else:
            new_name = conflict_name(dst_file)
            copy_file(src_file, new_name, follow_symlinks, dry_run, copy_sem)
            if fsync_before_delete and not dry_run:
                try:
                    fsync_file(new_name)
                except Exception as e:
                    logging.warning(f"fsync failed for {new_name}: {e}")
                    inc(counters, "errors")
            inc(counters, "renamed_conflicts")
            if delete_source:
                if safe_delete_if_unchanged(src_file, src_stat, dry_run):
                    inc(counters, "deleted")

    except Exception as e:
        logging.warning(f"Failed handling file {src_file}: {e}")
        inc(counters, "errors")
        add_failed(failed_files, str(src_file))

# ---------------- Main ----------------

def main():
    args = parse_args()
    setup_logging(args.verbose)

    src_root = Path(args.src).resolve()
    dst_root = Path(args.dst).resolve()

    # basic checks
    if not src_root.exists() or not src_root.is_dir():
        logging.error(f"Source not found or not a dir: {src_root}")
        sys.exit(2)
    if src_root == dst_root:
        logging.error("Source and destination must be different.")
        sys.exit(2)

    # forbid dst inside src (防止“自吞”)
    try:
        if dst_root.is_relative_to(src_root):  # py3.9+
            logging.error("Destination directory must NOT be inside the source directory.")
            sys.exit(2)
    except AttributeError:
        src_str, dst_str = str(src_root), str(dst_root)
        if os.path.commonpath([src_str, dst_str]) == src_str:
            logging.error("Destination directory must NOT be inside the source directory.")
            sys.exit(2)

    if not args.dry_run:
        try:
            dst_root.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logging.error(f"Cannot create destination {dst_root}: {e}")
            sys.exit(2)

    algo_name, new_hasher_fn = pick_hasher(args.algo)
    logging.info(
        f"Hash={algo_name} | quick={args.quick_bytes} | big≥{args.big_threshold} | "
        f"sampled(adaptive): chunk={args.sampled_chunk_size}, perGiB={args.samples_per_gib}, max={args.max_sampled_bytes} | "
        f"trust_name_size={args.trust_name_size} | trust_sampled={args.trust_sampled} | "
        f"video_sig={args.use_video_signature}, trust_video_sig={args.trust_video_signature} | "
        f"workers={args.workers}, max_copy={args.max_copy}, fsync_before_delete={args.fsync_before_delete}"
    )

    counters = {
        "copied": 0,
        "skipped_identical": 0,
        "renamed_conflicts": 0,
        "deleted": 0,
        "errors": 0,
    }
    failed_files: List[str] = []
    failed_dirs: List[str] = []

    copy_sem = threading.Semaphore(args.max_copy)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = []
        for src_file, rel_path in walk_files(src_root, args.ignore):
            futures.append(pool.submit(
                handle_one_file,
                src_file, rel_path, dst_root,
                args.quick_bytes, args.big_threshold,
                args.sampled_chunk_size, args.samples_per_gib, args.max_sampled_bytes,
                args.use_video_signature, args.trust_video_signature, args.trust_sampled, args.trust_name_size,
                new_hasher_fn, args.follow_symlinks,
                args.delete_source, args.fsync_before_delete, args.dry_run, copy_sem,
                counters, failed_files
            ))
        for _ in as_completed(futures):
            pass

    if args.delete_source:
        for dirpath, dirnames, filenames in os.walk(src_root, topdown=False):
            if filenames or dirnames:
                continue
            p = Path(dirpath)
            if args.keep_source_root and p == src_root:
                continue
            try:
                if args.dry_run:
                    logging.info(f"[DRY] RMDIR {p}")
                else:
                    p.rmdir()
            except Exception as e:
                logging.warning(f"Failed to remove dir {p}: {e}")
                inc(counters, "errors")
                add_failed(failed_dirs, str(p))

    moved_total = counters["copied"] + counters["renamed_conflicts"]

    print("\n=== Summary ===")
    print(f"Moved (new + conflicts): {moved_total}")
    print(f"  - New copied:          {counters['copied']}")
    print(f"  - Conflict renamed:    {counters['renamed_conflicts']}")
    print(f"Duplicates (skipped):    {counters['skipped_identical']}")
    print(f"Deleted source files:    {counters['deleted']}{'   (dry-run: deletions not executed)' if args.dry_run else ''}")
    print(f"Warnings/Errors:         {counters['errors']}")

    if failed_files:
        print("\n-- Failed/Skipped Files --")
        for p in failed_files:
            print(p)

    if failed_dirs:
        print("\n-- Failed Directories To Remove --")
        for d in failed_dirs:
            print(d)

if __name__ == "__main__":
    main()
