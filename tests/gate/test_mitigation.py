def test_gate_package_imports():
    import mylonite.gate  # noqa: F401
    from mylonite.gate import build_pr_body, run_gate, GateResult  # noqa: F401
