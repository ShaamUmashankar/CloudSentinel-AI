import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple
import numpy as np
import faiss
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

from config.config import Config
from database.db import get_db, query_all

class RAGSecurityAssistant:
    """
    Retrieval-Augmented Generation (RAG) Security Assistant.
    Ingests knowledge base markdown documents, chunks text, builds a FAISS vector index,
    retrieves contextual runbooks, and synthesizes incident explanations and remediation advice.
    Supports Google Gemini, OpenAI, or a clearly-labelled Fallback Demonstration Engine.
    """

    def __init__(self):
        self.kb_dir = Path(Config.KNOWLEDGE_BASE_DIR)
        self.index_path = Path(Config.FAISS_INDEX_PATH)
        self.vectorizer_path = self.index_path.parent / "vectorizer.joblib"
        self.chunks_meta_path = self.index_path.parent / "chunks_metadata.json"
        
        self.vectorizer: TfidfVectorizer = None
        self.faiss_index: faiss.IndexFlatIP = None
        self.chunks_metadata: List[Dict[str, Any]] = []
        
        self.load_or_build_index()

    def chunk_document(self, content: str, title: str, filename: str) -> List[Dict[str, Any]]:
        """Splits markdown content into semantic section chunks."""
        sections = re.split(r'\n(?=##?\s+)', content)
        chunks = []
        for idx, sec in enumerate(sections):
            sec_text = sec.strip()
            if len(sec_text) < 40:
                continue
            first_line = sec_text.split('\n')[0].replace('#', '').strip()
            chunk_title = f"{title} - {first_line}" if first_line else title
            chunks.append({
                "chunk_id": f"{filename}_{idx}",
                "document_title": title,
                "section_title": chunk_title,
                "source_file": filename,
                "text": sec_text
            })
        return chunks

    def build_index_from_disk(self) -> Dict[str, Any]:
        """Reads all markdown files in knowledge_base directory and constructs FAISS vector store."""
        all_chunks = []
        if not self.kb_dir.exists():
            self.kb_dir.mkdir(parents=True, exist_ok=True)

        md_files = list(self.kb_dir.glob("*.md"))
        if not md_files:
            return {"status": "EMPTY", "chunk_count": 0}

        # Store knowledge docs in SQLite
        with get_db() as conn:
            for md_path in md_files:
                with open(md_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Title from first header or filename
                lines = content.strip().split("\n")
                first_h1 = lines[0].replace("#", "").strip() if lines and lines[0].startswith("#") else md_path.stem.replace("_", " ").title()
                
                chunks = self.chunk_document(content, first_h1, md_path.name)
                all_chunks.extend(chunks)

                conn.execute("""
                    INSERT OR REPLACE INTO knowledge_docs (doc_id, title, category, source, content, chunk_count, indexed_at)
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                """, (
                    md_path.stem, first_h1, "Cloud Security", md_path.name, content, len(chunks)
                ))

        if not all_chunks:
            return {"status": "EMPTY_CHUNKS", "chunk_count": 0}

        # Vectorize chunks using TF-IDF dense projection
        corpus = [c["text"] for c in all_chunks]
        self.vectorizer = TfidfVectorizer(max_features=512, stop_words="english", ngram_range=(1, 2))
        tfidf_matrix = self.vectorizer.fit_transform(corpus).toarray().astype("float32")

        # L2-normalize vectors for Inner Product (Cosine Similarity)
        faiss.normalize_L2(tfidf_matrix)

        # Build FAISS IndexFlatIP
        d = tfidf_matrix.shape[1]
        self.faiss_index = faiss.IndexFlatIP(d)
        self.faiss_index.add(tfidf_matrix)
        self.chunks_metadata = all_chunks

        # Persist index and metadata
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self.faiss_index, str(self.index_path))
        joblib.dump(self.vectorizer, str(self.vectorizer_path))
        with open(self.chunks_meta_path, "w", encoding="utf-8") as f:
            json.dump(self.chunks_metadata, f, indent=2)

        return {
            "status": "INDEXED",
            "document_count": len(md_files),
            "chunk_count": len(all_chunks),
            "vector_dimension": d
        }

    def load_or_build_index(self):
        """Loads FAISS index and vectorizer from disk or builds fresh if missing."""
        if self.index_path.exists() and self.vectorizer_path.exists() and self.chunks_meta_path.exists():
            try:
                self.faiss_index = faiss.read_index(str(self.index_path))
                self.vectorizer = joblib.load(str(self.vectorizer_path))
                with open(self.chunks_meta_path, "r", encoding="utf-8") as f:
                    self.chunks_metadata = json.load(f)
                return
            except Exception as e:
                print(f"[RAG Warning] Failed to load cached FAISS index: {e}")
        
        self.build_index_from_disk()

    def retrieve_guidance(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Retrieves top-k relevant knowledge chunks using FAISS cosine similarity."""
        if not self.faiss_index or not self.vectorizer or not self.chunks_metadata:
            self.load_or_build_index()

        if not self.faiss_index or self.faiss_index.ntotal == 0:
            return []

        query_vec = self.vectorizer.transform([query]).toarray().astype("float32")
        faiss.normalize_L2(query_vec)

        scores, indices = self.faiss_index.search(query_vec, min(top_k, self.faiss_index.ntotal))
        
        results = []
        for rank, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.chunks_metadata):
                chunk = dict(self.chunks_metadata[idx])
                chunk["relevance_score"] = round(float(scores[0][rank]), 4)
                results.append(chunk)

        return results

    def analyze_incident(self, incident: Dict[str, Any], user_question: str = None) -> Dict[str, Any]:
        """
        Executes full RAG workflow for a security incident:
        1. Synthesizes search query from incident attributes
        2. Retrieves relevant security playbooks from FAISS
        3. Invokes LLM (Gemini, OpenAI) or Fallback Demonstration Engine
        4. Returns structured explanations, investigation steps, and containment guidance.
        """
        # Formulate query
        query_parts = [
            incident.get("title", ""),
            incident.get("event_name", ""),
            incident.get("rule_triggered", ""),
            incident.get("risk_factors", "")
        ]
        query = " ".join(p for p in query_parts if p)
        if user_question:
            query = f"{query} {user_question}"

        # Retrieve relevant playbooks
        retrieved_chunks = self.retrieve_guidance(query, top_k=3)

        # Decide LLM or Fallback
        provider = Config.LLM_PROVIDER
        if provider == "gemini" and Config.GEMINI_API_KEY:
            try:
                return self._generate_gemini_response(incident, retrieved_chunks, user_question)
            except Exception as e:
                print(f"[RAG Live Gemini Error] {e}. Falling back to demonstration engine.")
                return self._generate_fallback_response(incident, retrieved_chunks, user_question, fallback_reason=f"Gemini API connection error: {str(e)}")
        elif provider == "openai" and Config.OPENAI_API_KEY:
            try:
                return self._generate_openai_response(incident, retrieved_chunks, user_question)
            except Exception as e:
                print(f"[RAG Live OpenAI Error] {e}. Falling back to demonstration engine.")
                return self._generate_fallback_response(incident, retrieved_chunks, user_question, fallback_reason=f"OpenAI API error: {str(e)}")
        else:
            return self._generate_fallback_response(incident, retrieved_chunks, user_question)

    def _generate_fallback_response(self, incident: Dict[str, Any], chunks: List[Dict[str, Any]], user_question: str = None, fallback_reason: str = None) -> Dict[str, Any]:
        """
        Generates high-fidelity security analysis using retrieved knowledge chunks and incident telemetry.
        Explicitly labelled as Fallback Demonstration Mode to prevent misrepresentation.
        """
        event_name = incident.get("event_name", "UnknownEvent")
        principal = incident.get("principal", "UnknownPrincipal")
        source_ip = incident.get("source_ip", "UnknownIP")
        severity = incident.get("severity", "MEDIUM")
        ml_score = incident.get("ml_anomaly_score", 0.0)
        rule_name = incident.get("rule_triggered", "ML Anomaly Trigger")
        factors = incident.get("risk_factors", "Statistical anomaly")
        created_at = incident.get("event_time", incident.get("created_at", "Unknown Timestamp"))

        # Evidence context
        evidence_summary = f"- Event: {event_name} at {created_at}\n- Actor: {principal}\n- Origin IP: {source_ip}\n- Anomaly Score: {ml_score} (Severity: {severity})\n- Rule Flags: {rule_name}\n- Contributing Factors: {factors}"

        # Build investigation steps tailored to event type
        inv_steps = [
            f"Review CloudTrail history for principal '{principal}' over the past 24 hours to trace prior reconnaissance activity.",
            f"Verify whether source IP '{source_ip}' corresponds to an approved VPN endpoint, corporate IP range, or known NAT gateway.",
            f"Examine CloudWatch and VPC Flow Logs for contemporaneous network connections originating from '{source_ip}'.",
            "Confirm identity authenticity with the asset owner via out-of-band communication (Slack/Phone) to verify authorization."
        ]

        if "AttachUserPolicy" in event_name or "PutUserPolicy" in event_name:
            inv_steps.append("Audit all permissions granted in the attached policy to determine if AdministratorAccess or wildcard escalation was achieved.")
        elif "StopLogging" in event_name or "DeleteTrail" in event_name:
            inv_steps.append("Determine if other trails or AWS Config recording services were altered concurrently.")
        elif "ConsoleLogin" in event_name:
            inv_steps.append("Check if Multi-Factor Authentication (MFA) was challenged and whether subsequent console sessions succeeded.")

        # Remediation recommendations
        remediation_steps = [
            f"Assisted Containment: Revoke active session tokens for identity '{principal}' using temporary inline deny policy.",
            f"Credential Hygiene: Invalidate and rotate active AWS access keys associated with '{principal}'.",
            f"Network Defense: Add attacking IP '{source_ip}' to AWS WAF / VPC Network ACL drop list.",
            "Post-Incident: Conduct least-privilege permission review and re-enable automated CloudTrail monitoring safeguards."
        ]

        # Knowledge citations
        sources_cited = []
        for c in chunks:
            sources_cited.append({
                "title": c.get("document_title"),
                "section": c.get("section_title"),
                "file": c.get("source_file"),
                "relevance": c.get("relevance_score")
            })

        # Uncertainty statement
        uncertainty = (
            "Assessment Confidence: High on observed CloudTrail telemetry. "
            "Uncertainty Note: Corroborating endpoint EDR telemetry and VPC flow log packet captures are not present in this single log record. "
            "Immediate out-of-band confirmation with the principal is recommended before permanent credential deletion."
        )

        explanation = (
            f"Security Analysis for Incident {incident.get('incident_code', '')}:\n\n"
            f"The activity '{event_name}' executed by principal '{principal}' from IP '{source_ip}' represents a high-probability security incident. "
            f"Our ML Isolation Forest detector assigned an anomaly score of {ml_score} ({severity}), triggered by: {factors}. "
            f"In AWS security models, this pattern strongly aligns with attacker tactics outlined in our security knowledge base ({', '.join(s['title'] for s in sources_cited[:2])})."
        )

        if user_question:
            explanation += f"\n\nRegarding your question ('{user_question}'):\nBased on retrieved runbooks, this pattern typically signifies unauthorized access or credential compromise requiring immediate session quarantine."

        return {
            "provider": "Fallback Demonstration Engine (Curated Security Knowledge & ML Telemetry)",
            "is_fallback": True,
            "fallback_note": fallback_reason or "No external LLM API key configured in .env. Running in deterministic security demonstration mode using FAISS vector retrieval.",
            "incident_code": incident.get("incident_code"),
            "severity": severity,
            "ml_anomaly_score": ml_score,
            "explanation": explanation,
            "observed_evidence": evidence_summary,
            "investigation_steps": inv_steps,
            "remediation_recommendations": remediation_steps,
            "sources_cited": sources_cited,
            "uncertainty_assessment": uncertainty,
            "retrieved_chunks": chunks
        }

    def _generate_gemini_response(self, incident: Dict[str, Any], chunks: List[Dict[str, Any]], user_question: str = None) -> Dict[str, Any]:
        """Calls official Google GenAI SDK with structured system prompt and RAG context."""
        from google import genai
        
        client = genai.Client(api_key=Config.GEMINI_API_KEY)
        
        context_text = "\n\n".join([f"--- Source: {c['document_title']} ({c['source_file']}) ---\n{c['text']}" for c in chunks])
        
        prompt = f"""
You are CloudSentinel AI, an elite Cloud Security Operations Center (SOC) specialist.
Analyze this cloud security incident using ONLY the provided security knowledge base and observed log evidence.
Do not hallucinate external facts. State uncertainty if evidence is missing.

[Observed Incident Telemetry]
- Incident Code: {incident.get('incident_code')}
- Event Name: {incident.get('event_name')}
- Timestamp: {incident.get('event_time')}
- Principal: {incident.get('principal')}
- Source IP: {incident.get('source_ip')}
- Severity: {incident.get('severity')}
- ML Anomaly Score: {incident.get('ml_anomaly_score')}
- Rule Triggers: {incident.get('rule_triggered')}
- Risk Factors: {incident.get('risk_factors')}
- Raw Evidence: {incident.get('evidence_json')}

[Retrieved Security Knowledge Base Guidance]
{context_text}

[User Query]
{user_question or 'Provide comprehensive incident explanation, investigation steps, and remediation recommendations.'}

Respond in structured JSON format with the following keys:
"explanation", "observed_evidence", "investigation_steps" (list), "remediation_recommendations" (list), "uncertainty_assessment"
"""
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=prompt,
        )

        resp_text = response.text.strip()
        # Clean potential markdown JSON fences
        if resp_text.startswith("```json"):
            resp_text = resp_text[7:]
        if resp_text.endswith("```"):
            resp_text = resp_text[:-3]

        parsed = json.loads(resp_text)
        parsed["provider"] = "Google Gemini 2.0 Flash (Live LLM Inference)"
        parsed["is_fallback"] = False
        parsed["sources_cited"] = [{"title": c["document_title"], "file": c["source_file"], "relevance": c.get("relevance_score")} for c in chunks]
        parsed["retrieved_chunks"] = chunks
        return parsed

    def _generate_openai_response(self, incident: Dict[str, Any], chunks: List[Dict[str, Any]], user_question: str = None) -> Dict[str, Any]:
        """Placeholder for OpenAI provider if configured."""
        # Uses fallback with notification
        return self._generate_fallback_response(incident, chunks, user_question, fallback_reason="OpenAI provider configured, falling back to local FAISS demo mode")

    def get_status(self) -> Dict[str, Any]:
        """Returns RAG system status and index telemetry."""
        doc_count = len(query_all("SELECT id FROM knowledge_docs"))
        return {
            "llm_provider": Config.LLM_PROVIDER,
            "has_gemini_key": bool(Config.GEMINI_API_KEY),
            "has_openai_key": bool(Config.OPENAI_API_KEY),
            "faiss_index_ready": self.faiss_index is not None and self.faiss_index.ntotal > 0,
            "total_indexed_chunks": self.faiss_index.ntotal if self.faiss_index else 0,
            "knowledge_docs_count": doc_count,
            "index_path": str(self.index_path)
        }
