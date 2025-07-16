from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import GLiNERRecognizer


# Load a small spaCy model as we don't need spaCy's NER
nlp_engine = NlpEngineProvider(
    nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
)

# Create an analyzer engine
analyzer_engine = AnalyzerEngine()

# Define and create the GLiNER recognizer
entity_mapping = {
    "person": "PERSON",
    "name": "PERSON",
    "organization": "ORGANIZATION",
    "location": "LOCATION"
}

gliner_recognizer = GLiNERRecognizer(
    model_name="urchade/gliner_multi_pii-v1",
    entity_mapping=entity_mapping,
    flat_ner=False,
    multi_label=True,
    map_location="cpu",
)

# Add the GLiNER recognizer to the registry
analyzer_engine.registry.add_recognizer(gliner_recognizer)

# Remove the spaCy recognizer to avoid NER coming from spaCy
analyzer_engine.registry.remove_recognizer("SpacyRecognizer")

# Analyze text
results = analyzer_engine.analyze(
    text="Hello, my name is Rafi Mor, I'm from Binyamina and I work at Microsoft. ", language="en"
)

print(results)
