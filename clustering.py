#!/usr/bin/env python3
"""
Cluster XSS payload strings (typically WAF-bypass set) using char n-gram TF-IDF.

Input schema: JSON array of objects:
[
  {"id":"...","payload":"...","endpoint":"reflected|dom|stored","waf_bypass":true|false},
  ...
]

Output: JSON with clusters per endpoint (IDs only by default).
- By default, clusters only include item IDs (no payloads) to avoid leaking strings into logs.
- Optional: include a few representative payloads (redacted) if you pass --include_payload_snippets.

Dependencies:
  pip install scikit-learn
"""

import argparse
import html
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote_plus

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import AgglomerativeClustering, MiniBatchKMeans


UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
HEX_LONG_RE = re.compile(r"\b0x[0-9a-f]{8,}\b", re.IGNORECASE)
B64_LONG_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
WS_RE = re.compile(r"\s+")


def normalize_payload(s: str, *, decode_rounds: int = 1) -> str:
    """Normalize payload so clustering groups by structure, not by nonce/token."""
    if not isinstance(s, str):
        return ""

    x = s.strip().lower()

    # URL decode a limited number of rounds (avoid "decode bombs")
    for _ in range(max(0, decode_rounds)):
        x = unquote_plus(x)

    # HTML entity decode
    x = html.unescape(x)

    # Mask likely run-specific tokens
    x = UUID_RE.sub("<token>", x)
    x = HEX_LONG_RE.sub("<hex>", x)
    x = B64_LONG_RE.sub("<b64>", x)

    # Collapse whitespace
    x = WS_RE.sub(" ", x).strip()
    return x


@dataclass
class ClusterItem:
    id: str
    payload: str
    endpoint: str
    waf_bypass: bool


def load_items(path: Path) -> List[ClusterItem]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Input JSON must be an array of objects.")
    out: List[ClusterItem] = []
    for obj in raw:
        out.append(
            ClusterItem(
                id=str(obj.get("id", "")),
                payload=str(obj.get("payload", "")),
                endpoint=str(obj.get("endpoint", "unknown")),
                waf_bypass=bool(obj.get("waf_bypass", False)),
            )
        )
    return out


def build_tfidf(texts: List[str], ngram_lo: int, ngram_hi: int, min_df: int):
    vec = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(ngram_lo, ngram_hi),
        min_df=min_df,
        lowercase=False,  # already normalized
    )
    X = vec.fit_transform(texts)
    return vec, X


def cluster_hac_cosine(X, *, distance_threshold: float):
    """
    Agglomerative clustering with cosine metric.
    Note: some sklearn versions require dense input. We handle both.
    """
    model = AgglomerativeClustering(
        n_clusters=None,
        metric="cosine",
        linkage="average",
        distance_threshold=distance_threshold,
    )
    try:
        labels = model.fit_predict(X)  # works in newer sklearn
    except Exception:
        labels = model.fit_predict(X.toarray())  # fallback for older versions
    return labels


def cluster_kmeans(X, *, k: int, random_state: int = 42):
    model = MiniBatchKMeans(
        n_clusters=k,
        random_state=random_state,
        batch_size=1024,
        n_init="auto",
    )
    labels = model.fit_predict(X)
    return labels


def choose_representatives(
    items: List[ClusterItem],
    texts_norm: List[str],
    labels: List[int],
    max_per_cluster: int,
) -> Dict[int, List[Tuple[str, str]]]:
    """
    Return up to max_per_cluster representatives per cluster.
    To avoid leaking full payloads, we output small redacted snippets.
    """
    clusters: Dict[int, List[int]] = defaultdict(list)
    for idx, lab in enumerate(labels):
        clusters[int(lab)].append(idx)

    reps: Dict[int, List[Tuple[str, str]]] = {}
    for cid, idxs in clusters.items():
        chosen = idxs[:max_per_cluster]
        reps[cid] = []
        for i in chosen:
            # Redacted snippet (first 80 chars) of normalized text
            snippet = texts_norm[i][:80]
            reps[cid].append((items[i].id, snippet))
    return reps


def run_for_endpoint(
    items: List[ClusterItem],
    *,
    ngram_lo: int,
    ngram_hi: int,
    min_df: int,
    distance_threshold: float,
    hac_max_items: int,
    kmeans_k: int,
    decode_rounds: int,
    include_payload_snippets: bool,
    reps_per_cluster: int,
) -> Dict[str, Any]:
    texts_norm = [normalize_payload(it.payload, decode_rounds=decode_rounds) for it in items]
    _, X = build_tfidf(texts_norm, ngram_lo, ngram_hi, min_df)

    # Strategy: HAC for small/medium, KMeans for larger sets (HAC can be heavy)
    if len(items) <= hac_max_items:
        labels = cluster_hac_cosine(X, distance_threshold=distance_threshold)
        method = "hac_cosine"
        method_params = {"distance_threshold": distance_threshold}
    else:
        labels = cluster_kmeans(X, k=kmeans_k)
        method = "minibatch_kmeans"
        method_params = {"k": kmeans_k}

    clusters: Dict[int, List[str]] = defaultdict(list)
    for it, lab in zip(items, labels):
        clusters[int(lab)].append(it.id)

    out_clusters = []
    for cid, member_ids in sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True):
        entry: Dict[str, Any] = {
            "cluster_id": cid,
            "size": len(member_ids),
            "member_ids": member_ids,
        }
        out_clusters.append(entry)

    result: Dict[str, Any] = {
        "count": len(items),
        "method": method,
        "method_params": method_params,
        "vectorizer": {
            "type": "tfidf_char_wb",
            "ngram_range": [ngram_lo, ngram_hi],
            "min_df": min_df,
            "decode_rounds": decode_rounds,
        },
        "clusters": out_clusters,
    }

    if include_payload_snippets:
        reps = choose_representatives(items, texts_norm, labels, max_per_cluster=reps_per_cluster)
        # attach representatives
        rep_map = {cid: [{"id": rid, "norm_snippet": snip} for rid, snip in reps[cid]] for cid in reps}
        result["representatives"] = rep_map

    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input JSON file (array schema).")
    ap.add_argument("--out", dest="out", required=True, help="Output JSON file.")
    ap.add_argument("--only_bypass", action="store_true", help="Cluster only waf_bypass=true items.")
    ap.add_argument("--ngram_lo", type=int, default=3)
    ap.add_argument("--ngram_hi", type=int, default=6)
    ap.add_argument("--min_df", type=int, default=2)
    ap.add_argument("--distance_threshold", type=float, default=0.35, help="Used for HAC cosine.")
    ap.add_argument("--hac_max_items", type=int, default=2000, help="If more items, fall back to KMeans.")
    ap.add_argument("--kmeans_k", type=int, default=25, help="Used when falling back to KMeans.")
    ap.add_argument("--decode_rounds", type=int, default=1, help="URL-decode rounds in normalization.")
    ap.add_argument("--include_payload_snippets", action="store_true",
                   help="Include short normalized snippets (first 80 chars) for a few reps per cluster.")
    ap.add_argument("--reps_per_cluster", type=int, default=3)
    args = ap.parse_args()

    items = load_items(Path(args.inp))

    if args.only_bypass:
        items = [it for it in items if it.waf_bypass]
    # Group by endpoint first
    by_ep: Dict[str, List[ClusterItem]] = defaultdict(list)
    for it in items:
        by_ep[it.endpoint].append(it)

    out: Dict[str, Any] = {
        "input_file": str(Path(args.inp).resolve()),
        "only_bypass": args.only_bypass,
        "endpoints": {},
    }

    for ep, ep_items in by_ep.items():
        if len(ep_items) < 3:
            out["endpoints"][ep] = {
                "count": len(ep_items),
                "note": "Not enough items to cluster (need >=3).",
                "clusters": [],
            }
            continue

        out["endpoints"][ep] = run_for_endpoint(
            ep_items,
            ngram_lo=args.ngram_lo,
            ngram_hi=args.ngram_hi,
            min_df=args.min_df,
            distance_threshold=args.distance_threshold,
            hac_max_items=args.hac_max_items,
            kmeans_k=args.kmeans_k,
            decode_rounds=args.decode_rounds,
            include_payload_snippets=args.include_payload_snippets,
            reps_per_cluster=args.reps_per_cluster,
        )

    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote clusters -> {args.out}")


if __name__ == "__main__":
    main()
