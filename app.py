"""Streamlit entry point for the Sensitive Data Discovery Tool.

The UI is built in Phase 8 and will call into src/scanner.py rather than
duplicating any detection logic. Run with:

    streamlit run app.py
"""

import streamlit as st

st.set_page_config(page_title="Sensitive Data Discovery Tool", page_icon="🔍")
st.title("Sensitive Data Discovery Tool")
st.info("Project scaffold in place. The scan UI is built in Phase 8.")
