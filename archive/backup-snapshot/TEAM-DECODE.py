#!/usr/bin/env python3
"""TEAM-DECODE — High-Performance Compact Multi-Layer Auto-Decoder.
Modular Plugin Architecture.
"""
from __future__ import annotations
import argparse, json, os, shutil, sys, textwrap

import decoders
from core.models import Candidate
from core.heuristics import (
    detect_likely_block_cipher, _score_breakdown, safe_preview,
    DEFAULT_MAX_DEPTH, DEFAULT_BEAM_SIZE, DEFAULT_CANDIDATE_COUNT
)
from core.engine import (
    auto_decode, railfence_decode, vigenere_decode, columnar_decode
)

def terminal_width() -> int: return max(72, min(shutil.get_terminal_size((96, 24)).columns, 120))
def supports_color() -> bool: return not bool(os.environ.get("NO_COLOR")) and (sys.stdout.isatty() or os.name == "nt")

USE_COLOR    = supports_color()
SHOW_PROGRESS = sys.stdout.isatty()

def color(text: str, code: str) -> str: return f"\033[{code}m{text}\033[0m" if USE_COLOR else text
cyan   = lambda t: color(t, "36")
green  = lambda t: color(t, "32")
yellow = lambda t: color(t, "33")
dim    = lambda t: color(t, "2")

PROGRESS_BAR_WIDTH = 28

def render_progress_bar(current: int, total: int, label: str = "") -> str:
    total = max(total, 1); current = max(0, min(current, total))
    filled = int(PROGRESS_BAR_WIDTH * current / total)
    bar = "█" * filled + "░" * (PROGRESS_BAR_WIDTH - filled)
    return f"\r{dim('decoding')} {cyan('[')}{green(bar)}{cyan(']')} {int(100*current/total):3d}%  {dim(label)}\033[K"

def print_progress(current: int, total: int, label: str = "") -> None:
    if SHOW_PROGRESS: sys.stdout.write(render_progress_bar(current, total, label)); sys.stdout.flush()

def clear_progress_line() -> None:
    if SHOW_PROGRESS: sys.stdout.write("\r\033[K"); sys.stdout.flush()

def clear_screen() -> None: os.system("cls" if os.name == "nt" else "clear")

def divider(title: str = "") -> str:
    w = terminal_width()
    if not title: return dim("-" * w)
    lbl = f" {title} "; left = max(2, (w - len(lbl)) // 2); right = max(2, w - left - len(lbl))
    return dim("-" * left) + cyan(lbl) + dim("-" * right)

def print_banner() -> None:
    w = terminal_width()
    art = [
        " ████████╗███████╗ █████╗ ███╗   ███╗      ██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗",
        " ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝",
        "    ██║   █████╗  ███████║██╔████╔██║      ██║  ██║█████╗  ██║     ██║   ██║██║  ██║█████╗  ",
        "    ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║      ██║  ██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝  ",
        "    ██║   ███████╗██║  ██║██║ ╚═╝ ██║      ██████╔╝███████╗╚██████╗╚██████╔╝██████╔╝███████╗",
        "    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝",
        "", " > root@localhost:/home/team_decode# _"
    ]
    print(cyan("="*w)+"\n"+color("CRYPTO UTILITY — SECURE MULTIBASE DECODER 🔑".center(w),"1;33")+"\n"+color("20+ encodings • smart heuristics • safe preview".center(w),"1;33")+"\n")
    groups = [
        ("Binary",["base2"]),("Radix/Base",["base16","base32","base36","base45","base58","base62","base64","base64url","base100"]),
        ("High-enc",["base85","ascii85","z85","base91","base92"]),
        ("Text/Other",["morse","url","quoted_printable","rotN","rot47","rot5","rot18","atbash","xor_singlebyte","reverse"])
    ]
    col_w = max(20, w // len(groups))
    print("".join(cyan(title.center(col_w)) for title, _ in groups).center(w))
    wrapped_lists = [textwrap.wrap(", ".join(items), width=col_w-2) or [""] for _, items in groups]
    for i in range(max(len(wl) for wl in wrapped_lists)):
        print("".join(dim((wl[i] if i < len(wl) else "").center(col_w)) for wl in wrapped_lists).center(w))
    print("\n" + cyan("="*w))
    for line in art: print(green(line.center(w)))
    print("\n"+yellow("🏠 q = quit 🧹 c = clear ❓  h/help/? = help   ⏎ empty = input")
          +"    "+color("💳 Create by Mr.Suchakree Panyawong","1;35")+"\n\n"+cyan("="*w))

def print_help() -> None:
    print(divider("Help")+"\nPaste one encoded value per prompt. The tool will recursively try known decoders.\n"
          "The decode chain is shown in the order used to decode.\n"
          "Commands Quick: q = quit, c = clear terminal, h/help/? = show help, empty input = new prompt\n")
    print(divider("Tier-3 Manual Commands")+"\nThese are NOT auto-chained (too ambiguous / false-positive prone). Invoke them explicitly:\n"
          +f"  {cyan('railfence')} <rails> <text>     e.g. railfence 3 WECRLTEERDSOEEFEAOCAIVDEN\n"
          +f"  {cyan('vigenere')} <key> <text>         e.g. vigenere LEMON ATTACKATDAWN\n"
          +f"  {cyan('columnar')} <key> <text>         e.g. columnar 4 WECRLTEERDSOEEFEAOCAIVDEN\n")

def _get_crypto_hint(winner: Candidate, raw_input: str | None) -> str | None:
    hint = detect_likely_block_cipher(winner.text) if not winner.chain else None
    return detect_likely_block_cipher(raw_input) if (hint is None and raw_input is not None) else hint

def format_result_json(candidates: list[Candidate], candidate_count: int = DEFAULT_CANDIDATE_COUNT, raw_input: str | None = None) -> dict:
    winner = candidates[0]
    return {
        "winner": {"text": winner.text, "chain": list(winner.chain), "score": round(winner.score,4), "score_breakdown": _score_breakdown(winner.text)},
        "candidates": [{"rank": i+1, "text": c.text, "chain": list(c.chain), "score": round(c.score,4)} for i,c in enumerate(candidates[:candidate_count])],
        "crypto_hint": _get_crypto_hint(winner, raw_input),
    }

def print_result(candidates: list[Candidate], show_candidates: bool, candidate_count: int = DEFAULT_CANDIDATE_COUNT, raw_input: str | None = None) -> None:
    winner = candidates[0]
    chain = " -> ".join(winner.chain) if winner.chain else "(input looked already decoded)"
    print(divider("Best Guess") + f"\n{green(winner.text)}\n\n{cyan('Decode chain: ')}{chain}\n{dim(f'Score: {winner.score:.2f}')}")
    if (crypto_hint := _get_crypto_hint(winner, raw_input)): print(f"\n{yellow(crypto_hint)}")
    if show_candidates:
        print("\n" + divider("Top Candidates"))
        for index, candidate in enumerate(candidates[:candidate_count], start=1):
            cand_chain = " -> ".join(candidate.chain) if candidate.chain else "original"
            print(f"{yellow(f'{index:02d}.')} score={candidate.score:.2f}  chain={cand_chain}\n    {safe_preview(candidate.text)}")

def handle_manual_command(raw_input: str) -> bool:
    parts = raw_input.split(None, 2)
    if len(parts) < 3: return False
    cmd = parts[0].lower()
    if cmd == "railfence":
        try: rails = int(parts[1])
        except ValueError: return False
        res = railfence_decode(parts[2], rails)
        print(divider("Rail Fence Result")+f"\n{green(res) if res else dim('(invalid rail count for this input length)')}\n"); return True
    if cmd == "vigenere":
        res = vigenere_decode(parts[2], parts[1])
        print(divider("Vigenère Result")+f"\n{green(res) if res else dim('(invalid key)')}\n"); return True
    if cmd == "columnar":
        try: width = int(parts[1])
        except ValueError: return False
        res = columnar_decode(parts[2], width)
        print(divider("Columnar Transposition Result")+f"\n{green(res) if res else dim('(invalid key width for this input length)')}\n"); return True
    return False

def read_payload(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle: return handle.read().strip()
    if args.value: return args.value
    raise SystemExit("Provide an encoded value or use -f/--file.")

def run_interactive(max_depth: int, beam_size: int, show_candidates: bool) -> None:
    print_banner()
    while True:
        print(divider())
        try: payload = input(cyan("encoded> ")).strip()
        except (EOFError, KeyboardInterrupt): print("\n" + dim("bye")); return
        if not payload: continue
        if payload.lower() in {"q","quit","exit"}: print(dim("bye")); return
        if payload.lower() == "c": clear_screen(); continue
        if payload.lower() in {"h","help","?"}: print_help(); continue
        if handle_manual_command(payload): continue
        _on_prog = lambda depth, total, explored: print_progress(depth, total, label=f"layer {depth}/{total} · {explored} explored")
        candidates = auto_decode(payload, max_depth=max_depth, beam_size=beam_size, progress_callback=_on_prog)
        clear_progress_line(); print_result(candidates, show_candidates=show_candidates, raw_input=payload); print()

def main() -> None:
    parser = argparse.ArgumentParser(description="God-Tier Auto-decode multi-layer encoded text.")
    parser.add_argument("value", nargs="?", help="Encoded text to decode")
    parser.add_argument("-f","--file", help="Read encoded text from a file")
    parser.add_argument("-m","--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Maximum decode layers")
    parser.add_argument("-b","--beam-size", type=int, default=DEFAULT_BEAM_SIZE, help="Number of candidates to keep per layer")
    parser.add_argument("--show-candidates", action="store_true", help="Print top candidate results")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of human output")
    args = parser.parse_args()
    if not args.value and not args.file:
        run_interactive(max_depth=args.max_depth, beam_size=args.beam_size, show_candidates=False); return
    payload = read_payload(args)
    _on_prog = lambda depth, total, explored: (print_progress(depth, total, label=f"layer {depth}/{total} · {explored} explored") if not args.json else None)
    candidates = auto_decode(payload, max_depth=args.max_depth, beam_size=args.beam_size, progress_callback=_on_prog)
    if not args.json:
        clear_progress_line(); print_result(candidates, show_candidates=args.show_candidates, candidate_count=10, raw_input=payload)
    else:
        if sys.stdout.encoding.lower() != 'utf-8': sys.stdout.reconfigure(encoding='utf-8')
        print(json.dumps(format_result_json(candidates, candidate_count=10, raw_input=payload), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
