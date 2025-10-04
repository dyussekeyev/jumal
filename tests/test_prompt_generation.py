from core.summarizer import Summarizer
from core.aggregator import Aggregator
import logging

def test_prompt_basic():
    logger = logging.getLogger("test")
    config = {"ui": {"default_language": "en"}}
    summ = Summarizer(logger, config)
    agg_struct = {
        "basic": {
            "detections": 5,
            "type_description": "Win32 EXE",
            "size": 12345,
            "names": ["sample.exe"]
        },
        "mitre": ["T1059 Command and Scripting Interpreter"],
        "processes": ["cmd.exe"],
        "network": ["1.2.3.4"],
        "comments": ["Suspicious sample"],
        "yara_ruleset": None,
        "sigma_rules": None
    }
    prompt = summ.build_prompt("System prompt", agg_struct)
    assert "Detections: 5" in prompt
    assert "T1059" in prompt