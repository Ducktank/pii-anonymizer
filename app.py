"""
PII Anonymizer - Streamlit Web Interface
A privacy-first interface for querying LLMs with sensitive data.
"""

import streamlit as st
from anonymizer import PIIAnonymizer
from llm_client import get_client, MockLLMClient
import os

# Page config
st.set_page_config(
    page_title="PII Anonymizer for LLMs",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state
if "anonymizer" not in st.session_state:
    st.session_state.anonymizer = PIIAnonymizer()

if "messages" not in st.session_state:
    st.session_state.messages = []

if "current_mapping" not in st.session_state:
    st.session_state.current_mapping = {}


def highlight_pii(text: str, entities: list) -> str:
    """Create HTML with highlighted PII entities."""
    if not entities:
        return text
    
    # Sort entities by start position (reverse for safe replacement)
    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    
    result = text
    colors = {
        "PERSON": "#ff6b6b",
        "PHONE_NUMBER": "#4ecdc4",
        "EMAIL_ADDRESS": "#45b7d1",
        "US_SSN": "#f9ca24",
        "CREDIT_CARD": "#f0932b",
        "DATE_TIME": "#a55eea",
        "LOCATION": "#26de81",
        "MEDICAL_RECORD_NUMBER": "#fd79a8",
        "NPI": "#00cec9",
    }
    
    for entity in sorted_entities:
        color = colors.get(entity["entity_type"], "#95a5a6")
        original = text[entity["start"]:entity["end"]]
        highlighted = f'<span style="background-color: {color}; padding: 2px 4px; border-radius: 3px; color: white;" title="{entity["entity_type"]} ({entity["score"]:.0%})">{original}</span>'
        result = result[:entity["start"]] + highlighted + result[entity["end"]:]
    
    return result


def main():
    st.title("🔒 PII Anonymizer for LLMs")
    st.markdown("*Protect sensitive data when querying AI assistants*")
    
    # Sidebar settings
    with st.sidebar:
        st.header("⚙️ Settings")
        
        # LLM Provider
        use_mock = st.checkbox("Use Mock LLM (no API key needed)", value=True)
        
        if not use_mock:
            provider = st.selectbox("LLM Provider", ["claude", "openai"])
            
            if provider == "claude":
                api_key = st.text_input("Anthropic API Key", type="password", 
                                        value=os.getenv("ANTHROPIC_API_KEY", ""))
                if api_key:
                    os.environ["ANTHROPIC_API_KEY"] = api_key
            else:
                api_key = st.text_input("OpenAI API Key", type="password",
                                        value=os.getenv("OPENAI_API_KEY", ""))
                if api_key:
                    os.environ["OPENAI_API_KEY"] = api_key
        else:
            provider = "mock"
        
        st.divider()
        
        # Confidence threshold
        confidence = st.slider(
            "Detection Confidence Threshold",
            min_value=0.3,
            max_value=1.0,
            value=0.7,
            step=0.05,
            help="Higher = fewer false positives, lower = catch more PII"
        )
        st.session_state.anonymizer.confidence_threshold = confidence
        
        st.divider()
        
        # Entity types to detect
        st.subheader("Entity Types")
        all_entities = st.session_state.anonymizer.DEFAULT_ENTITIES
        selected_entities = st.multiselect(
            "Detect these PII types:",
            options=all_entities,
            default=all_entities
        )
        
        st.divider()
        
        # Reset button
        if st.button("🗑️ Clear Session", use_container_width=True):
            st.session_state.anonymizer.reset()
            st.session_state.messages = []
            st.session_state.current_mapping = {}
            st.rerun()
    
    # Main content area - two columns
    col1, col2 = st.columns(2)
    
    with col1:
        st.header("📝 Your Input")
        
        # Example text
        example_text = """Patient John Smith, DOB 03/15/1982, SSN 123-45-6789, 
was seen at Boston General Hospital. 
Contact: john.smith@email.com, phone 410-555-1234.
MRN: 12345678, NPI: 1234567890

Please summarize this patient's visit and recommend next steps."""
        
        user_input = st.text_area(
            "Enter your query (may contain PII):",
            value=example_text,
            height=200,
            key="user_input"
        )
        
        # Analyze button
        if st.button("🔍 Analyze PII", use_container_width=True):
            if user_input:
                entities = st.session_state.anonymizer.analyze(user_input, selected_entities)
                
                st.subheader("Detected PII:")
                if entities:
                    # Show highlighted text
                    highlighted = highlight_pii(user_input, entities)
                    st.markdown(highlighted, unsafe_allow_html=True)
                    
                    # Show entity table
                    st.markdown("---")
                    for entity in entities:
                        st.markdown(f"- **{entity['entity_type']}**: `{entity['text']}` ({entity['score']:.0%} confidence)")
                else:
                    st.success("No PII detected!")
    
    with col2:
        st.header("🤖 Anonymized Query")
        
        if st.button("🚀 Anonymize & Send to LLM", use_container_width=True, type="primary"):
            if user_input:
                with st.spinner("Processing..."):
                    # Anonymize
                    anonymized_text, mapping = st.session_state.anonymizer.anonymize(
                        user_input, selected_entities
                    )
                    st.session_state.current_mapping = mapping
                    
                    # Show anonymized version
                    st.subheader("Anonymized Input:")
                    st.code(anonymized_text, language=None)
                    
                    # Show mapping
                    if mapping:
                        with st.expander("🔑 PII Mapping (kept locally)"):
                            for placeholder, original in mapping.items():
                                st.text(f"{placeholder} → {original}")
                    
                    # Send to LLM
                    st.subheader("LLM Response:")
                    try:
                        client = get_client(provider=provider, mock=use_mock)
                        
                        # Get response
                        response = client.chat(
                            anonymized_text,
                            system_prompt="You are a helpful medical assistant. Respond to queries using the placeholder names provided (like [PERSON_1]) rather than making up names."
                        )
                        
                        # Show anonymized response
                        st.markdown("**Anonymized response:**")
                        st.info(response)
                        
                        # De-anonymize
                        restored_response = st.session_state.anonymizer.deanonymize(
                            response, mapping
                        )
                        
                        st.markdown("**De-anonymized response:**")
                        st.success(restored_response)
                        
                        # Save to history
                        st.session_state.messages.append({
                            "input": user_input,
                            "anonymized_input": anonymized_text,
                            "response": response,
                            "restored_response": restored_response,
                            "mapping": mapping
                        })
                        
                    except Exception as e:
                        st.error(f"Error calling LLM: {str(e)}")
    
    # History section
    if st.session_state.messages:
        st.divider()
        st.header("📜 Conversation History")
        
        for i, msg in enumerate(reversed(st.session_state.messages)):
            with st.expander(f"Query {len(st.session_state.messages) - i}", expanded=(i == 0)):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Original Input:**")
                    st.text(msg["input"][:200] + "..." if len(msg["input"]) > 200 else msg["input"])
                with col_b:
                    st.markdown("**Final Response:**")
                    st.text(msg["restored_response"][:200] + "..." if len(msg["restored_response"]) > 200 else msg["restored_response"])


if __name__ == "__main__":
    main()
