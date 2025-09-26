#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import logging
from pathlib import Path
from collections import Counter, defaultdict
from typing import Iterable, Optional, Dict, List
import pandas as pd

# ---------- tqdm (progress bar) ----------
try:
    from tqdm import tqdm  # pip install tqdm
except Exception:
    def tqdm(it: Iterable, total: Optional[int] = None, desc: Optional[str] = None, **k):
        return it

# ---------- Logging ----------
def setup_logger(out_dir: Path, log_file: Optional[str] = None, verbose: bool = True) -> logging.Logger:
    out_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("aiops-pipeline")
    logger.setLevel(logging.INFO)
    # avoid duplicate handlers if re-imported
    if logger.handlers:
        return logger
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")
    if verbose:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        logger.addHandler(ch)
    lf = log_file if log_file else str(out_dir / "pipeline.log")
    fh = logging.FileHandler(lf, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

# ---------- PREPROCESS (Qin et al., 2024) ----------
SPACE = re.compile(r'\s+')
RE_DT_FULL  = re.compile(r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?\b')
RE_DT_WORDY = re.compile(r'\b(?:mon|tue|wed|thu|fri|sat|sun|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*'
                         r'(?:\s+\d{1,2})?(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?\b', re.IGNORECASE)
RE_IPV4_PORT= re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?!$))){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?::\d{1,5})?\b')
RE_DOMAIN   = re.compile(r'\b(?:(?:[a-z0-9\-]+\.)+[a-z]{2,})(?::\d{1,5})?\b', re.IGNORECASE)
RE_URL      = re.compile(r'\b[a-z]{2,10}://[^\s"\'<>]+', re.IGNORECASE)
RE_PATH     = re.compile(r'(?<!\w)(/[^ \t\n\r\f\v"<>]+)(?!\w)')
RE_PKG      = re.compile(r'\b[a-zA-Z_][\w$]*(?:[:.][a-zA-Z_][\w$]*){2,}\b')
RE_SIZE     = re.compile(r'\b\d+(?:\.\d+)?\s?(?:b|kb|mb|gb|tb|kib|mib|gib|tib)\b', re.IGNORECASE)
RE_TDUR     = re.compile(r'\b\d+(?:\.\d+)?\s?(?:ns|us|ms|s|sec|m|min|h|hr|d|day|w)\b', re.IGNORECASE)
RE_MAC      = re.compile(r'\b[0-9a-f]{2}(?:[:\-][0-9a-f]{2}){5}\b', re.IGNORECASE)
RE_HEX      = re.compile(r'\b0x[0-9a-fA-F]+\b|\b[0-9A-Fa-f]{8,}\b')
RE_QUOTED   = re.compile(r'\".*?\"|\'.*?\'')
RE_NUM      = re.compile(r'(?<![A-Za-z])[-+]?\d+(?:\.\d+)?(?![A-Za-z])')
RE_NODE1    = re.compile(r'\bR\d{1,2}-M\d{1,2}-N\d{1,3}\b', re.IGNORECASE)
RE_NODE2    = re.compile(r'\bC?n\d{1,3}\b', re.IGNORECASE)
RE_IPV6     = re.compile(r'\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b', re.IGNORECASE)
RE_ANGLE    = re.compile(r'<\s*?>')

def preprocess_line(line: str, collapse_to_generic: bool) -> str:
    s = line.rstrip('\n').lower()
    for pat, tag in [(RE_QUOTED,'<STR>'),(RE_URL,'<URL>'),(RE_IPV6,'<IPV6>'),(RE_IPV4_PORT,'<IP>'),
                     (RE_DOMAIN,'<DOMAIN>'),(RE_NODE1,'<NODE>'),(RE_NODE2,'<NODE>'),(RE_PATH,'<PATH>'),
                     (RE_PKG,'<PKG>'),(RE_MAC,'<MAC>'),(RE_SIZE,'<SIZE>'),(RE_TDUR,'<TDUR>'),
                     (RE_DT_FULL,'<DT>'),(RE_DT_WORDY,'<DT>'),(RE_HEX,'<HEX>'),(RE_NUM,'<NUM>')]:
        s = pat.sub(tag, s)
    s = SPACE.sub(' ', s).strip()
    s = RE_ANGLE.sub('<*>', s)
    if collapse_to_generic:
        s = re.sub(r'<[A-Z]+>', '<*>', s)
    return s

# ---------- STREAMING PREPROCESS ----------
def streaming_preprocess(raw_log: Path, out_path: Path, use_typed: bool, sample_lines: Optional[int], logger: logging.Logger) -> int:
    """Stream raw log to a preprocessed file; return #lines written. Skips if file exists."""
    if out_path.exists():
        logger.info(f"[skip] Preprocessed already exists: {out_path}")
        try:
            return sum(1 for _ in out_path.open("rb"))
        except Exception:
            return -1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        total = sum(1 for _ in raw_log.open('rb'))
    except Exception:
        total = None

    n = 0
    with raw_log.open('r', errors='ignore') as fin, out_path.open('w') as fout:
        for line in tqdm(fin, total=total, desc="Pré-traitement (streaming)"):
            fout.write(preprocess_line(line, collapse_to_generic=not use_typed) + "\n")
            n += 1
            if sample_lines and n >= sample_lines:
                break
    logger.info(f"[done] Preprocessed -> {out_path} (lines={n})")
    return n

# ---------- DRAIN (LogPAI) ----------
def run_drain(preprocessed_path: Path, out_tmp_dir: Path, st=0.4, depth=4, max_child=100, use_typed=False, force=False, logger: Optional[logging.Logger]=None) -> Path:
    """
    Run LogPAI Drain and return the path to the produced *_structured.csv.
    Skips if ANY *_structured.csv already exists unless force=True.
    """
    from logparser.Drain import LogParser
    out_tmp_dir.mkdir(parents=True, exist_ok=True)

    # If any drain output already exists, skip (fast resume)
    existing = sorted(out_tmp_dir.glob("*_structured.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if existing and not force:
        if logger: logger.info(f"[skip] Drain already completed: {existing[0].name}")
        return existing[0]

    rex = ([r"<DT>", r"<IP>", r"<DOMAIN>", r"<URL>", r"<PATH>", r"<PKG>", r"<MAC>",
            r"<SIZE>", r"<TDUR>", r"<IPV6>", r"<HEX>", r"<STR>", r"<NUM>", r"<NODE>"]
           if use_typed else [r"<\*>"])

    if logger:
        logger.info(f"[run] Running Drain on {preprocessed_path.name} (depth={depth}, st={st}, maxChild={max_child})")

    parser = LogParser(
        log_format="<Content>",
        indir=str(preprocessed_path.parent),
        outdir=str(out_tmp_dir),
        depth=depth,
        st=st,
        rex=rex,
        maxChild=max_child,
        keep_para=True,
    )
    tqdm([0], desc="Drain parsing").__iter__()  # cosmetic progress bar
    parser.parse(preprocessed_path.name)

    # Locate latest structured file robustly
    outputs = sorted(out_tmp_dir.glob("*_structured.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not outputs:
        raise FileNotFoundError(f"Drain did not produce *_structured.csv in {out_tmp_dir}")
    if logger: logger.info(f"[done] Drain output: {outputs[0].name}")
    return outputs[0]

# ---------- BUILD OUTPUTS (CHUNKS) ----------
def build_outputs(structured_csv: Path, raw_log: Path, out_dir: Path, chunksize: int, force: bool, logger: logging.Logger, block_regex: str):
    """
    Create:
      - log_template.csv
      - event_occurrences.csv
      - event_traces.csv

    IMPORTANT: BlockId is extracted from the RAW LOG (raw_log) by LineId alignment,
    not from the (masked) Content field.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    log_template_path = out_dir / "log_template.csv"
    occ_path         = out_dir / "event_occurrences.csv"
    traces_path      = out_dir / "event_traces.csv"
    structured_copy  = out_dir / "structured.csv"

    # If everything exists and not forcing, skip entirely
    if log_template_path.exists() and occ_path.exists() and traces_path.exists() and structured_copy.exists() and not force:
        logger.info("[skip] All outputs already exist.")
        return

    # Ensure regex has a capturing group (required by pandas.str.extract; we use re directly here)
    if "(" not in block_regex or ")" not in block_regex:
        logger.warning("[warn] block_regex has no capture group; adding one automatically.")
        block_regex = f"({block_regex})"
    block_re = re.compile(block_regex, re.IGNORECASE)

    occurrences = Counter()
    first_template: Dict[str, str] = {}
    traces: Dict[str, List[str]] = defaultdict(list)
    saw_any_rows = False

    # Open raw log for aligned reads
    raw_fh = raw_log.open("r", errors="ignore")
    next_raw_line_id = 1  # 1-based LineId alignment

    try:
        for chunk in tqdm(pd.read_csv(structured_csv, chunksize=chunksize), desc="Lecture structured.csv (chunks)"):
            if len(chunk) == 0:
                continue
            saw_any_rows = True

            cols = {c.lower() for c in chunk.columns}
            if "eventid" not in cols or "eventtemplate" not in cols:
                raise RuntimeError("EventId / EventTemplate missing in structured.csv.")

            # Ensure LineId present (synthesize if missing)
            if "lineid" not in cols:
                start = 1 if not hasattr(build_outputs, "_lineid") else build_outputs._lineid + 1
                end = start + len(chunk) - 1
                chunk.insert(0, "LineId", range(start, end + 1))
                build_outputs._lineid = end  # type: ignore[attr-defined]

            chunk.rename(columns={c: c.lower() for c in chunk.columns}, inplace=True)

            # Aggregate occurrences & first template
            occurrences.update(chunk["eventid"].astype(str))
            for eid, tmpl in zip(chunk["eventid"].astype(str), chunk["eventtemplate"].astype(str)):
                if eid not in first_template:
                    first_template[eid] = tmpl

            # ===== Extract BlockId from RAW by aligning LineId range =====
            min_lid = int(chunk["lineid"].min())
            max_lid = int(chunk["lineid"].max())

            # Fast-forward raw file if needed
            while next_raw_line_id < min_lid:
                _ = raw_fh.readline()
                next_raw_line_id += 1

            # Read raw lines for the [min_lid, max_lid] range and extract BlockId
            raw_blocks_for_range: List[Optional[str]] = []
            for lid in range(min_lid, max_lid + 1):
                raw_line = raw_fh.readline()
                if not raw_line:
                    logger.warning(f"[warn] raw_log ended early at line {lid}")
                    raw_blocks_for_range.append(None)
                    next_raw_line_id = lid + 1
                    continue
                m = block_re.search(raw_line)
                raw_blocks_for_range.append(m.group(1).lower() if m else None)
                next_raw_line_id = lid + 1

            # Map (LineId -> BlockId) and merge to chunk (LineId, EventId)
            blk_map = pd.DataFrame({"LineId": list(range(min_lid, max_lid + 1)), "BlockId": raw_blocks_for_range})
            merged = chunk[["lineid", "eventid"]].merge(blk_map, left_on="lineid", right_on="LineId", how="left")
            merged = merged.drop(columns=["LineId"]).dropna(subset=["BlockId"]).sort_values("lineid")

            for blk, eid in zip(merged["BlockId"].astype(str), merged["eventid"].astype(str)):
                traces[blk].append(eid)
    finally:
        raw_fh.close()

    if not saw_any_rows:
        logger.error(f"[error] structured csv appears empty: {structured_csv}")
        # write empty outputs to avoid loops
        pd.DataFrame(columns=["EventId","EventTemplate"]).to_csv(log_template_path, index=False)
        pd.DataFrame(columns=["EventId","Occurrences"]).to_csv(occ_path, index=False)
        pd.DataFrame(columns=["BlockId","EventSequence"]).to_csv(traces_path, index=False)
        return

    # Write outputs (skip individually if present unless force)
    if not log_template_path.exists() or force:
        pd.DataFrame({
            "EventId": list(first_template.keys()),
            "EventTemplate": [first_template[k] for k in first_template.keys()]
        }).sort_values("EventId").to_csv(log_template_path, index=False)
        logger.info(f"[write] {log_template_path}")
    else:
        logger.info(f"[skip] {log_template_path} already exists")

    if not occ_path.exists() or force:
        pd.DataFrame({
            "EventId": list(occurrences.keys()),
            "Occurrences": list(occurrences.values())
        }).sort_values(["Occurrences", "EventId"], ascending=[False, True]).to_csv(occ_path, index=False)
        logger.info(f"[write] {occ_path}")
    else:
        logger.info(f"[skip] {occ_path} already exists")

    if not traces_path.exists() or force:
        pd.DataFrame({
            "BlockId": list(traces.keys()),
            "EventSequence": list(traces.values())
        }).to_csv(traces_path, index=False)
        logger.info(f"[write] {traces_path}")
    else:
        logger.info(f"[skip] {traces_path} already exists")

    # Copy structured.csv next to outputs (for reference)
    if not structured_copy.exists() or force:
        try:
            pd.read_csv(structured_csv).to_csv(structured_copy, index=False)
            logger.info(f"[write] {structured_copy}")
        except Exception as e:
            logger.warning(f"[warn] Could not copy structured.csv: {e}")
    else:
        logger.info(f"[skip] {structured_copy} already exists")

def main(raw_log: str, out_dir="out_hdfs",
         st=0.4, depth=4, max_child=100,
         use_typed=False, chunksize=200_000, sample_lines: Optional[int]=None,
         force: bool=False, log_file: Optional[str]=None, verbose: bool=True,
         block_regex: str="(blk_[\\-]?\\d+)"):

    raw_log = Path(raw_log).expanduser().resolve()
    out_dir = Path(out_dir).resolve()
    tmp_dir = out_dir / "drain_tmp"

    logger = setup_logger(out_dir, log_file=log_file, verbose=verbose)
    logger.info(f"Start | input={raw_log} out={out_dir} use_typed={use_typed} force={force} block_regex={block_regex!r}")

    # 1) Streaming preprocess (skip if exists unless force)
    preproc_path = tmp_dir / ("preprocessed_typed.log" if use_typed else "preprocessed_collapsed.log")
    if preproc_path.exists() and not force:
        logger.info(f"[skip] Using existing preprocessed file: {preproc_path}")
    else:
        n_lines = streaming_preprocess(raw_log, preproc_path, use_typed, sample_lines, logger)
        logger.info(f"[info] Preprocessed lines: {n_lines}")

    # 2) Run (or skip) Drain
    structured_path = run_drain(preproc_path, tmp_dir, st=st, depth=depth, max_child=max_child, use_typed=use_typed, force=force, logger=logger)
    logger.info(f"[info] structured csv: {structured_path}")

    # 3) Build outputs (skip individually if exist unless force) — uses RAW log for BlockId
    build_outputs(structured_csv=structured_path,
                  raw_log=raw_log,
                  out_dir=out_dir,
                  chunksize=chunksize,
                  force=force,
                  logger=logger,
                  block_regex=block_regex)

    logger.info("Done ✅")
    logger.info(f"Outputs:\n- {out_dir/'log_template.csv'}\n- {out_dir/'event_occurrences.csv'}\n- {out_dir/'event_traces.csv'}\n- {out_dir/'structured.csv'}")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("-i","--input", required=True, help="Path to raw log (e.g., HDFS.log)")
    ap.add_argument("-o","--out", default="out_hdfs", help="Output directory")
    ap.add_argument("--st", type=float, default=0.4, help="Drain similarity threshold")
    ap.add_argument("--depth", type=int, default=4, help="Drain tree depth")
    ap.add_argument("--max_child", type=int, default=100, help="Max children per node")
    ap.add_argument("--use_typed", action="store_true", help="Use typed placeholders (<DT>, <IP>, …) instead of collapsing to <*>")
    ap.add_argument("--chunksize", type=int, default=200000, help="Pandas chunksize for reading structured.csv")
    ap.add_argument("--sample_lines", type=int, default=None, help="Only preprocess first N lines (perf/debug)")
    ap.add_argument("--force", action="store_true", help="Recompute even if outputs exist")
    ap.add_argument("--log_file", type=str, default=None, help="Custom log file (default: <out>/pipeline.log)")
    ap.add_argument("--no-verbose", dest="verbose", action="store_false", help="Disable console logging (still logs to file)")
    ap.add_argument("--block_regex", type=str, default="(blk_[\\-]?\\d+)", help="Regex WITH a CAPTURE GROUP for BlockId (default matches HDFS blk IDs)")
    args = ap.parse_args()
    main(args.input, args.out, args.st, args.depth, args.max_child, args.use_typed, args.chunksize, args.sample_lines, args.force, args.log_file, args.verbose, args.block_regex)
