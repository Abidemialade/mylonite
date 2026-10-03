# 2. Choose a model

Mylonite has no default provider and no default model. `demo`'s replay (step
1) needed none; every command from here on that makes an LLM call does, and
checks for it before touching your target.

The full provider table, how to hand over a key, and which commands need one
at all are on [Choose a model](../choose-a-model.md) — this page doesn't
repeat that table, since it's generated from the same registry the CLI
checks against and would drift from it if copied here by hand.

Pick one of two paths:

- **A hosted provider.** Anthropic is the one this journey is measured
  against (`claude-haiku-4-5-20251001`); OpenAI, Gemini, Azure, Bedrock and a
  few others are supported — see the table for each one's key variable.

  ```bash
  export MYLONITE_MODEL=anthropic/claude-haiku-4-5-20251001
  export ANTHROPIC_API_KEY=sk-ant-...
  ```

- **No key at all: a local model.** [Self-hosted models](../self-hosted-models.md)
  covers Ollama and vLLM in full. The honest version of that page's guidance,
  stated here because it changes what you should expect from the rest of
  this journey: a small (3B-class) local model is what fits a laptop or a
  default CI runner without being killed for memory, and a 3B model is
  measurably worse at both roles Mylonite's calls play — the planner driving
  your tools, and the judge deciding whether damage actually happened. Run
  one and a clean result on your own app can mean the attack wasn't tried
  properly, not that your app is safe; treat a 3B run as **a smoke run**
  for steps 1-4, and use a hosted model (or a larger self-hosted one) before
  trusting a [kept finding](5-prove.md) or its absence.

  ```bash
  export MYLONITE_MODEL=ollama_chat/llama3.2:3b
  export MYLONITE_API_BASE=http://localhost:11434
  ```

With none of `--model`, `mylonite.yaml`'s `model:`, or `MYLONITE_MODEL` set,
every live command stops before touching a target, naming the approved
providers and their key variables, and exits `4`.

## Next

[3. Point at your app](3-point-at-your-app.md) — the first step that needs
your own server, still free.
