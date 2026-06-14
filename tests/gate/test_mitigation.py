def test_gate_package_imports():
    import mylonite.gate  # noqa: F401
    from mylonite.gate import GateResult, build_pr_body, run_gate  # noqa: F401
