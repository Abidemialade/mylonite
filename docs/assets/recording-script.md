# Recording the Quarry demo GIF

This page is the controller script for producing `docs/assets/quarry-demo.gif`
— the GIF embedded at the top of the README. **The actual recording is a
human / controller step done post-merge**; this doc just pins down exactly
what gets recorded so the result is reproducible.

- **Output path:** `docs/assets/quarry-demo.gif`
- **Target length:** ≤ 60 seconds.
- **Tool:** any terminal-to-GIF recorder works — e.g.
  [terminalizer](https://github.com/faressoft/terminalizer), or
  [asciinema](https://asciinema.org/) plus
  [agg](https://github.com/asciinema/agg) (or `asciicast2gif`) to convert the
  cast to a GIF. Don't over-engineer it; pick whatever produces a clean,
  legible loop.

## Setup (off-camera)

Do the clone-first install **once, before recording** — it is slow and not
interesting on camera. Use a clean checkout and a fresh virtualenv:

```bash
git clone https://github.com/Abidemialade/mylonite.git
cd mylonite
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install -e ./reference_targets/mcp_kitchen_sink
```

Then size the terminal for a crisp GIF: ~100 columns × ~30 rows, a high-
contrast theme, and a large monospace font. Clear the scrollback so the
recording starts on a blank prompt.

## On-camera (the recorded segment)

Record exactly one command:

```bash
mylonite demo
```

That is the whole take. `mylonite demo` is offline and deterministic (it
replays committed fixtures — no API key, no network), so the output is the
same every run and the GIF will always match what a viewer gets.

## Narration beats and timing

The GIF has no audio; "narration" here means the on-screen rhythm to aim for.
Budget against the ≤ 60s target:

| Time     | Beat                                                                 |
| -------- | ------------------------------------------------------------------- |
| 0–2s     | Blank prompt; type `mylonite demo` and hit enter.                   |
| 2–6s     | **Safety banner** appears: in-process, loopback-only, no network.   |
| 6–18s    | Scan #1 runs against the **vulnerable** Quarry — W1–W4 land.        |
| 18–30s   | Scan #2 runs against the **guarded** twin — all clean.              |
| 30–40s   | The **W1–W4 weakness table** with OWASP / ASI / ATLAS taxonomy IDs. |
| 40–48s   | The headline: **`4 exploits on vulnerable, 0 on guarded`**.         |
| 48–55s   | The `mode: replay (offline)` line; hold a beat on the final frame.  |

Trim dead air so the whole thing stays under a minute, then loop cleanly back
to the blank prompt.

## Post-recording

Export to `docs/assets/quarry-demo.gif`, keep the file small enough to embed
comfortably in the README (optimize/downscale if needed), and confirm the
README embed (`![Mylonite demo](docs/assets/quarry-demo.gif)`) renders.
