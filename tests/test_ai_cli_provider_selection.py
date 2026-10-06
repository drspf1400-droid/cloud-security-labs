from argparse import Namespace
from functools import partial

from modules.ai_providers import (
    ollama_json_analyzer,
)

from scripts.analyze_assessment_ai import (
    DEFAULT_OLLAMA_MODEL,
    build_analyzer,
)


def test_cli_selects_ollama_provider_without_network():
    args = Namespace(
        provider="ollama",
        model=None,
        endpoint=(
            "http://127.0.0.1:11434/api/chat"
        ),
        timeout=30,
    )

    (
        analyzer,
        provider_name,
        model_name,
    ) = build_analyzer(args)

    assert provider_name == "ollama"
    assert model_name == DEFAULT_OLLAMA_MODEL

    assert isinstance(
        analyzer,
        partial,
    )

    assert (
        analyzer.func
        is ollama_json_analyzer
    )

    assert (
        analyzer.keywords["endpoint"]
        ==
        "http://127.0.0.1:11434/api/chat"
    )

    assert (
        analyzer.keywords["timeout"]
        == 30
    )
