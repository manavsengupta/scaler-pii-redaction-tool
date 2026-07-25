# 🔒 PII Redaction Tool - Scaler Assignment

hey everyone! this is my code repository for the Scaler AI Labs assignment. basically i built a smart PII (personally identifiable information) cleaning tool that takes large `.docx` files (like 100+ page legal prospectuses), finds all the sensitive personal data, and replaces it with fake dummy data while keeping the original document formatting, tables, and XML structure completely intact.

---

## 💡 Why i built it this way (The Problem)

when u run standard out-of-the-box NLP redaction models on real Indian corporate documents, two super annoying things happen:
1. **The "For Example" Bug:** normal models love to over-redact. they see capitalized table headers or conversational words like *"For example"*, *"Server Logs"*, or *"Was Detected"* and mistakenly swap them out as human names (`PERSON`) or companies (`ORG`).
2. **Indian Name Blindspot:** western-trained language models often get confused by traditional Indian names (like *"Subbayya"* or *"Malvadkar"*) and think they are verbs or common nouns, leaving the actual sensitive name sitting right there in the document.

to fix this, i built a custom verification layer over **Microsoft Presidio** and **spaCy** using offline name databases and specific regex rules.

---

## ✨ Key Features & Highlights

* **🛡️ False-Positive Shield:** connected an offline database of over 100 million real names (`names-dataset`). before my code removes any word as a person's name, it cross-checks the db. if it's not a registered name, it uses spaCy grammar checking to see if it's just a normal verb/preposition and leaves it alone.
* **🔁 Substring Entity Vault (Consistency):** used a persistent Python dictionary (`self.mp`) to save mappings. if *"Kushal Hegde"* becomes *"John Lewis"* on page 1, any later mention or partial mention (like just *"Hegde"*) anywhere in the 128 pages automatically gets mapped to the exact same replacement.
* **🇮🇳 Indian & Global PII Support:** added custom regex patterns for:
  * **Indian Data:** PAN cards, Aadhaar numbers, +91 phone numbers, and 6-digit postal PIN codes.
  * **Global Data:** names, email addresses, physical addresses, US SSNs, IPv4 addresses, credit cards, and birth dates.
* **🎯 Safer All-Caps Handling:** instead of converting every sentence to title-case (which creates a mess of false positives), the script only runs shadow parsing on words that are strictly ALL-CAPS.
* **📊 Automated Audit Logging:** simultaneously generates a clean spreadsheet (`audit_report.csv`) saving every single replacement, timestamp, original text, fake word used, and confidence score so u can audit precision and recall easily.

---

## 🛠️ Tech Stack Used

* **Language:** Python 3.10+
* **Core Engine:** Microsoft Presidio (`presidio-analyzer`, `presidio-anonymizer`)
* **NLP Model:** spaCy (`en_core_web_lg`)
* **Verification & Fake Data:** `names-dataset`, `Faker`
* **Document Handling:** `python-docx`
* **UI & Data:** `streamlit`, `pandas`

---

## 🚀 How to Run Locally

### 1. clone the repo and install packages
make sure u have python installed and create a virtual env if u want, then run:
```bash
git clone [https://github.com/your-username/scaler-pii-redaction-tool.git](https://github.com/your-username/scaler-pii-redaction-tool.git)
cd scaler-pii-redaction-tool
pip install -r requirements.txt

```

*(note: the spacy english large model is linked directly in requirements.txt so it downloads automatically without linking errors)*

### 2. run the web app (Streamlit UI)

if u want the drag-and-drop web interface with instant download buttons:

```bash
streamlit run app.py

```

then open your browser at `http://localhost:8501`.

### 3. run as standalone script

if u just wanna run the command line script on a document directly:

```bash
python pii_redactor.py

```

*(just put your input file as `input_document.docx` in the root folder before running)*

---

## 📂 Output Files Generated

once the cleaning is done, the app gives u 2 files:

1. **`redacted_output.docx`**: your original word document with all private data cleaned and replaced by realistic fake data, with tables and formatting untouched.
2. **`audit_report.csv`**: a summary log of everything that got changed:

| Timestamp | Entity Type | Original Text | Synthetic Replacement | Confidence Score |
| --- | --- | --- | --- | --- |
| 2026-07-25 11:04:55 | `PERSON` | Rajesh Kushal Hegde | Tammy Allison | 0.90 |
| 2026-07-25 11:04:55 | `IN_PAN` | NBWPS1951N | LXRPT4829K | 0.95 |
| 2026-07-25 11:04:57 | `EMAIL_ADDRESS` | cs.connect@ksh.com | patrickhoward@example.com | 1.00 |

---

## 🧠 Practical Trade-offs & Edge Cases Noticed

while inspecting the final output on the massive test document, i noticed some interesting real-world edge cases:

* **Non-Greedy Company Regex:** standard regex patterns for words ending in `"Limited"` or `"Ltd."` often greedily swallow whole 15-word sentences if they happen to start with a capital letter and end with Limited. i capped the organization length strictly to 1–7 words while allowing connectors like `&` and `and`.
* **Country Names vs Addresses:** when the model caught words like "India" or "Sweden", it tagged them as `LOCATION`. since my Faker location generator creates full 4-line street addresses, country names became full addresses. splitting location tags into `COUNTRY` and `STREET` in the future will make table cells look much cleaner.
* **Scanned Images:** at the very end of the test document, there are embedded photos of ID cards. since this script only works on the XML text layer, text inside images is bypassed.

---

## 🔮 Future Scope

to make this 100% production ready, the next step would be adding **Multimodal OCR (like Tesseract or AWS Textract)**. this would let the tool read text inside scanned ID card photos or annexure images, run the exact same PII detection logic, and apply visual black-box masking over sensitive numbers before exporting.

---

*built with lots of patience and debugging for Scaler AI Labs!*

```

```
