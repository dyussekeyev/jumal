from core.summarizer import Summarizer
import logging

def test_extract_json_and_text():
    logger = logging.getLogger("test")
    config = {"ui": {"default_language": "en"}}
    summ = Summarizer(logger, config)
    text = '{"verdict":"malicious","confidence":90,"key_capabilities":["steals data"],"mitre_techniques":["T1059"],"recommended_actions":["isolate"],"raw_summary":"desc"}\nDetailed analysis...'
    js, free = summ.extract_json_and_text(text)
    assert js is not None
    assert js["verdict"] == "malicious"
    assert "Detailed analysis" in free