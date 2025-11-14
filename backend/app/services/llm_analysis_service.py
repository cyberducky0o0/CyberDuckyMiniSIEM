"""
LLM Analysis Service - AI-Powered Log Analysis
Uses local LLM (Ollama) for intelligent security analysis
Provides: Classification, Summarization, Risk Scoring, Structured Output
"""
import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.services.ollama_service import OllamaService
from app.models.log_entry import LogEntry
from app.models.anomaly import Anomaly

logger = logging.getLogger(__name__)


class LLMAnalysisService:
    """
    Service for LLM-powered security log analysis
    Optimized for small models (phi3:mini, gemma:2b)
    """
    
    def __init__(self, model: str = "phi3:mini"):
        """
        Initialize LLM Analysis Service
        
        Args:
            model: Ollama model to use (phi3:mini, gemma:2b, llama3:instruct, mistral:tiny)
        """
        self.ollama = OllamaService(default_model=model)
        self.model = model
        
        # System prompts for different tasks
        self.SYSTEM_PROMPTS = {
            "classification": "You are a SOC analyst assistant. Categorize security events accurately and concisely.",
            "risk_scoring": "You are a cybersecurity risk analyst. Assess threats objectively based on evidence.",
            "summarization": "You are a security analyst. Summarize events clearly and highlight critical information.",
            "investigation": "You are a threat hunter. Analyze patterns and provide actionable insights."
        }
        
        logger.info(f"Initialized LLM Analysis Service with model: {model}")
    
    def is_available(self) -> bool:
        """Check if LLM service is available"""
        return self.ollama.is_available()
    
    def classify_log_event(self, log_entry: LogEntry) -> Dict[str, Any]:
        """
        Classify a single log event using LLM
        
        Args:
            log_entry: LogEntry to classify
            
        Returns:
            Classification result with category, confidence, reasoning
        """
        # Build concise prompt
        prompt = f"""Categorize this web proxy log into one of: [normal, suspicious, malicious].

Log Details:
- User: {log_entry.username or 'unknown'}
- URL: {log_entry.url or log_entry.hostname or 'unknown'}
- Category: {log_entry.url_category or 'unknown'}
- Action: {log_entry.action or 'unknown'}
- Threat: {log_entry.threat_name or 'none'}
- Risk Score: {log_entry.risk_score or 0}

Respond with JSON only:
{{"category": "normal|suspicious|malicious", "confidence": 0.0-1.0, "reason": "brief explanation"}}"""
        
        result = self.ollama.generate_json(
            prompt=prompt,
            system=self.SYSTEM_PROMPTS["classification"],
            temperature=0.1
        )
        
        if result.get("success"):
            data = result["data"]
            return {
                "category": data.get("category", "unknown"),
                "confidence": float(data.get("confidence", 0.5)),
                "reason": data.get("reason", ""),
                "model": self.model
            }
        else:
            logger.error(f"LLM classification failed: {result.get('error')}")
            return {
                "category": "unknown",
                "confidence": 0.0,
                "reason": f"LLM error: {result.get('message', 'unknown')}",
                "model": self.model,
                "error": True
            }
    
    def score_risk(self, log_entry: LogEntry, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Score risk of a log event using LLM
        
        Args:
            log_entry: LogEntry to score
            context: Additional context (user history, patterns, etc.)
            
        Returns:
            Risk score (0-100), reasoning, and indicators
        """
        # Build context-aware prompt
        context_str = ""
        if context:
            if context.get("request_count"):
                context_str += f"\n- User made {context['request_count']} requests in last hour"
            if context.get("blocked_count"):
                context_str += f"\n- {context['blocked_count']} requests were blocked"
            if context.get("unique_domains"):
                context_str += f"\n- Accessed {context['unique_domains']} unique domains"
        
        prompt = f"""Rate this security event's risk from 0-100 and explain briefly.

Event Details:
- User: {log_entry.username or 'unknown'}
- URL: {log_entry.url or log_entry.hostname or 'unknown'}
- Category: {log_entry.url_category or 'unknown'}
- Action: {log_entry.action or 'unknown'}
- Threat: {log_entry.threat_name or 'none'}
- Response Code: {log_entry.response_code or 'unknown'}
- Bytes: {log_entry.destination_bytes or 0}{context_str}

Respond with JSON only:
{{"risk_score": 0-100, "severity": "low|medium|high|critical", "reason": "brief explanation", "indicators": ["indicator1", "indicator2"]}}"""
        
        result = self.ollama.generate_json(
            prompt=prompt,
            system=self.SYSTEM_PROMPTS["risk_scoring"],
            temperature=0.1
        )
        
        if result.get("success"):
            data = result["data"]
            return {
                "risk_score": int(data.get("risk_score", 50)),
                "severity": data.get("severity", "medium"),
                "reason": data.get("reason", ""),
                "indicators": data.get("indicators", []),
                "model": self.model
            }
        else:
            logger.error(f"LLM risk scoring failed: {result.get('error')}")
            return {
                "risk_score": 50,
                "severity": "medium",
                "reason": f"LLM error: {result.get('message', 'unknown')}",
                "indicators": [],
                "model": self.model,
                "error": True
            }
    
    def summarize_events(self, log_entries: List[LogEntry], max_entries: int = 50) -> Dict[str, Any]:
        """
        Summarize multiple log events using LLM
        
        Args:
            log_entries: List of LogEntry objects
            max_entries: Maximum entries to include in summary
            
        Returns:
            Summary text, key findings, and statistics
        """
        if not log_entries:
            return {
                "summary": "No events to summarize",
                "key_findings": [],
                "statistics": {}
            }
        
        # Limit entries to avoid token limits
        entries = log_entries[:max_entries]
        
        # Build concise event list
        event_lines = []
        for i, entry in enumerate(entries, 1):
            event_lines.append(
                f"{i}. {entry.username or 'unknown'} → {entry.hostname or 'unknown'} "
                f"[{entry.url_category or 'unknown'}] {entry.action or 'unknown'}"
            )
        
        events_text = "\n".join(event_lines)
        
        prompt = f"""Summarize these {len(entries)} web proxy events in one paragraph highlighting anomalies and threats.

Events:
{events_text}

Respond with JSON only:
{{"summary": "1-2 paragraph summary", "key_findings": ["finding1", "finding2", "finding3"], "threat_level": "low|medium|high|critical"}}"""
        
        result = self.ollama.generate_json(
            prompt=prompt,
            system=self.SYSTEM_PROMPTS["summarization"],
            temperature=0.2
        )
        
        if result.get("success"):
            data = result["data"]
            return {
                "summary": data.get("summary", ""),
                "key_findings": data.get("key_findings", []),
                "threat_level": data.get("threat_level", "medium"),
                "events_analyzed": len(entries),
                "model": self.model
            }
        else:
            logger.error(f"LLM summarization failed: {result.get('error')}")
            return {
                "summary": f"Failed to generate summary: {result.get('message', 'unknown')}",
                "key_findings": [],
                "threat_level": "unknown",
                "events_analyzed": len(entries),
                "model": self.model,
                "error": True
            }
    
    def analyze_anomaly(self, anomaly: Anomaly, log_entry: Optional[LogEntry] = None) -> Dict[str, Any]:
        """
        Provide LLM-powered analysis of an anomaly
        
        Args:
            anomaly: Anomaly object
            log_entry: Associated LogEntry (optional)
            
        Returns:
            Analysis with explanation, recommendations, and next steps
        """
        # Build context
        context = f"""Anomaly Type: {anomaly.anomaly_type}
Severity: {anomaly.severity}
Title: {anomaly.title}
Description: {anomaly.description}
Affected User: {anomaly.affected_user or 'unknown'}
Affected IP: {anomaly.affected_ip or 'unknown'}
Detection Method: {anomaly.detection_method or 'unknown'}"""
        
        if log_entry:
            context += f"""
URL: {log_entry.url or log_entry.hostname or 'unknown'}
Category: {log_entry.url_category or 'unknown'}
Action: {log_entry.action or 'unknown'}"""
        
        prompt = f"""Analyze this security anomaly and provide actionable recommendations for a SOC analyst.

{context}

Respond with JSON only:
{{"explanation": "what this means", "recommendations": ["action1", "action2", "action3"], "urgency": "low|medium|high|critical", "next_steps": ["step1", "step2"]}}"""
        
        result = self.ollama.generate_json(
            prompt=prompt,
            system=self.SYSTEM_PROMPTS["investigation"],
            temperature=0.2
        )
        
        if result.get("success"):
            data = result["data"]
            return {
                "explanation": data.get("explanation", ""),
                "recommendations": data.get("recommendations", []),
                "urgency": data.get("urgency", "medium"),
                "next_steps": data.get("next_steps", []),
                "model": self.model
            }
        else:
            logger.error(f"LLM anomaly analysis failed: {result.get('error')}")
            return {
                "explanation": f"Analysis failed: {result.get('message', 'unknown')}",
                "recommendations": [],
                "urgency": "unknown",
                "next_steps": [],
                "model": self.model,
                "error": True
            }

    def detect_attack_pattern(self, log_entries: List[LogEntry]) -> Dict[str, Any]:
        """
        Detect attack patterns across multiple log entries

        Args:
            log_entries: List of LogEntry objects (typically from same user/IP)

        Returns:
            Pattern detection results with attack type, confidence, and IOCs
        """
        if not log_entries:
            return {"pattern": "none", "confidence": 0.0, "description": "No events"}

        # Build pattern summary
        entries = log_entries[:20]  # Limit to avoid token limits

        # Aggregate statistics
        categories = {}
        actions = {}
        threats = set()

        for entry in entries:
            cat = entry.url_category or 'unknown'
            categories[cat] = categories.get(cat, 0) + 1

            act = entry.action or 'unknown'
            actions[act] = actions.get(act, 0) + 1

            if entry.threat_name and entry.threat_name != 'UNKNOWN':
                threats.add(entry.threat_name)

        prompt = f"""Analyze these web proxy events for attack patterns.

Statistics:
- Total Events: {len(entries)}
- Categories: {dict(list(categories.items())[:5])}
- Actions: {dict(actions)}
- Threats Detected: {list(threats)[:5] if threats else ['none']}
- Time Span: {entries[0].timestamp} to {entries[-1].timestamp}

Common attack patterns: SQL injection, XSS, malware download, C2 communication, data exfiltration, brute force, reconnaissance

Respond with JSON only:
{{"pattern": "attack_type or none", "confidence": 0.0-1.0, "description": "brief explanation", "iocs": ["ioc1", "ioc2"]}}"""

        result = self.ollama.generate_json(
            prompt=prompt,
            system=self.SYSTEM_PROMPTS["investigation"],
            temperature=0.1
        )

        if result.get("success"):
            data = result["data"]
            return {
                "pattern": data.get("pattern", "none"),
                "confidence": float(data.get("confidence", 0.0)),
                "description": data.get("description", ""),
                "iocs": data.get("iocs", []),
                "events_analyzed": len(entries),
                "model": self.model
            }
        else:
            return {
                "pattern": "unknown",
                "confidence": 0.0,
                "description": f"Analysis failed: {result.get('message', 'unknown')}",
                "iocs": [],
                "events_analyzed": len(entries),
                "model": self.model,
                "error": True
            }

    def generate_investigation_report(
        self,
        anomalies: List[Anomaly],
        log_entries: List[LogEntry],
        user: Optional[str] = None,
        ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive investigation report using LLM

        Args:
            anomalies: List of related anomalies
            log_entries: List of related log entries
            user: Username being investigated
            ip: IP address being investigated

        Returns:
            Investigation report with findings, timeline, and recommendations
        """
        # Build investigation context
        subject = user or ip or "Unknown Entity"

        # Anomaly summary
        anomaly_types = {}
        for anomaly in anomalies[:10]:
            atype = anomaly.anomaly_type
            anomaly_types[atype] = anomaly_types.get(atype, 0) + 1

        # Event summary
        categories = {}
        blocked = 0
        for entry in log_entries[:50]:
            cat = entry.url_category or 'unknown'
            categories[cat] = categories.get(cat, 0) + 1
            if entry.action == 'blocked':
                blocked += 1

        prompt = f"""Generate a security investigation report for: {subject}

Findings:
- Total Anomalies: {len(anomalies)}
- Anomaly Types: {dict(list(anomaly_types.items())[:5])}
- Total Events: {len(log_entries)}
- Blocked Requests: {blocked}
- Categories Accessed: {dict(list(categories.items())[:5])}

Respond with JSON only:
{{
  "executive_summary": "2-3 sentence overview",
  "threat_assessment": "low|medium|high|critical",
  "key_findings": ["finding1", "finding2", "finding3"],
  "timeline": "brief timeline of events",
  "recommendations": ["action1", "action2", "action3"],
  "requires_escalation": true|false
}}"""

        result = self.ollama.generate_json(
            prompt=prompt,
            system=self.SYSTEM_PROMPTS["investigation"],
            temperature=0.2
        )

        if result.get("success"):
            data = result["data"]
            return {
                "subject": subject,
                "executive_summary": data.get("executive_summary", ""),
                "threat_assessment": data.get("threat_assessment", "medium"),
                "key_findings": data.get("key_findings", []),
                "timeline": data.get("timeline", ""),
                "recommendations": data.get("recommendations", []),
                "requires_escalation": data.get("requires_escalation", False),
                "anomalies_count": len(anomalies),
                "events_count": len(log_entries),
                "generated_at": datetime.utcnow().isoformat(),
                "model": self.model
            }
        else:
            return {
                "subject": subject,
                "executive_summary": f"Report generation failed: {result.get('message', 'unknown')}",
                "threat_assessment": "unknown",
                "key_findings": [],
                "timeline": "",
                "recommendations": [],
                "requires_escalation": False,
                "anomalies_count": len(anomalies),
                "events_count": len(log_entries),
                "generated_at": datetime.utcnow().isoformat(),
                "model": self.model,
                "error": True
            }

