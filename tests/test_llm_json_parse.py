from core.summarizer import Summarizer
import logging

def test_extract_json_and_text():
    logger = logging.getLogger("test")
    config = {"ui": {"default_language": "en"}}
    summ = Summarizer(logger, config)
    # Include Cyrillic in JSON and free text to verify Unicode handling
    text = '{"verdict":"malicious","confidence":90,"key_capabilities":["steals data","Кража данных"],"mitre_techniques":["T1059"],"recommended_actions":["isolate"],"raw_summary":"desc"}\nDetailed analysis with Cyrillic: Подробный анализ...'
    js, free = summ.extract_json_and_text(text)
    assert js is not None
    assert js["verdict"] == "malicious"
    # Verify Cyrillic is preserved in key_capabilities
    assert "Кража данных" in js["key_capabilities"]
    # Verify Cyrillic is present in free text
    assert "Detailed analysis" in free
    assert "Подробный анализ" in free

def test_extract_json_pretty():
    logger = logging.getLogger("test")
    config = {"ui": {"default_language": "en"}}
    summ = Summarizer(logger, config)
    # Test with Cyrillic to verify Unicode preservation in pretty output
    text = '{"verdict":"suspicious","confidence":75,"key_capabilities":["Отправка данных","network activity"],"mitre_techniques":["T1071"],"recommended_actions":["monitor","Мониторинг"],"raw_summary":"Russian summary: Образец демонстрирует сетевую активность"}\nFree text analysis: Дополнительная информация...'
    js, pretty, free = summ.extract_json_pretty(text)
    
    # Verify JSON parsed correctly
    assert js is not None
    assert js["verdict"] == "suspicious"
    assert js["confidence"] == 75
    
    # Verify Cyrillic characters are NOT escaped in pretty output (no \u041e etc.)
    assert pretty is not None
    assert "Отправка данных" in pretty
    assert "Мониторинг" in pretty
    assert "Образец демонстрирует сетевую активность" in pretty
    # Ensure no Unicode escapes appear
    assert "\\u" not in pretty
    
    # Verify free text remains intact with Cyrillic
    assert "Free text analysis" in free
    assert "Дополнительная информация" in free
    
    # Verify pretty formatting (indentation)
    assert "\n" in pretty
    assert "  " in pretty  # Check for indentation