import os
import json
import requests
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from openai import OpenAI 

# Import configuration from your config.py
from src.config import LLM_API_KEY, LLM_MODEL_NAME, LLM_PROMPT_TEMPLATE_PATH, LLM_MAX_TOKENS, LLM_FALLBACK_MODEL_NAME

# ==============================================================================
# 1. Pydantic Data Models (The "Schema") - EXPORTED
# ==============================================================================

# NOTE: These classes are defined at the top-level so they can be imported
# by other modules, like core_logic.py, which uses them for type hinting.

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    UNKNOWN = "UNKNOWN"

class LogID(BaseModel):
    log_id: str = Field(description="The unique ID extracted from the log line (e.g., LOGID-001)")

class IPAddress(BaseModel):
    ip_address: str = Field(description="IPv4 address found in the log")

class ResponseCode(BaseModel):
    response_code: str = Field(description="HTTP response status code or System Event ID")

class WebTrafficPattern(BaseModel):
    url_path: str
    http_method: str
    hits_count: int
    response_codes: Dict[str, int]
    unique_ips: int

class WebSecurityEvent(BaseModel):
    relevant_log_entry_ids: List[LogID] = Field(default_factory=list)
    reasoning: str
    event_type: str
    severity: SeverityLevel
    confidence_score: float
    url_pattern: str
    http_method: str
    source_ips: List[IPAddress] = Field(default_factory=list)
    possible_attack_patterns: List[AttackType] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

class LogAnalysis(BaseModel):
    summary: str
    observations: List[str] = Field(default_factory=list)
    planning: List[str] = Field(default_factory=list)
    events: List[WebSecurityEvent] = Field(default_factory=list)
    traffic_patterns: List[WebTrafficPattern] = Field(default_factory=list)
    highest_severity: Optional[SeverityLevel] = SeverityLevel.INFO
    requires_immediate_attention: bool = False


# ==============================================================================
# 2. The AI Service Wrapper
# ==============================================================================

class STRESSED:
    """
    Connects to the Cloud LLM API (OpenRouter) to perform forensic analysis.
    Enforces structured JSON output using Pydantic validation.
    """
    def __init__(self):
        # Initialize the OpenAI Client for OpenRouter
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=LLM_API_KEY,
            default_headers={
                "HTTP-Referer": "https://github.com/AiLogGuard", 
                "X-Title": "AI LAD",
            }
        )
        self.model_name = LLM_MODEL_NAME
        
        # Load the Prompt Template
        try:
            # Using an absolute path check to be safer
            template_path = os.path.abspath(LLM_PROMPT_TEMPLATE_PATH) 
            with open(template_path, "r", encoding="utf-8") as f:
                self.prompt_template = f.read()
        except Exception as e:
            print(f"[LLM Service] Error loading prompt template: {e}")
            self.prompt_template = "Analyze these {log_type} logs: {logs}. Schema: {model_schema}"

    def analyze_logs(self, logs: List[str], log_type: str = "Web Server Access Logs", retry_count: int = 0) -> LogAnalysis:
        """
        Sends logs to the LLM and returns a structured LogAnalysis object.
        Includes retry logic for handling truncated responses.
        """
        # 1. Pre-process Logs
        # When retrying, use fewer logs to reduce token consumption and get faster responses
        if retry_count > 0:
            max_logs = max(5, 20 - (retry_count * 5))  # Reduce by 5 logs per retry
        else:
            max_logs = 20
        
        chunked_logs = logs[-max_logs:]
        
        log_lines_with_ids = []
        for idx, line in enumerate(chunked_logs):
            log_id = f"LOGID-{idx:03d}" 
            log_lines_with_ids.append(f"[{log_id}] {line}")
            
        logs_text = "\n".join(log_lines_with_ids)

        # 2. Get the JSON Schema from Pydantic
        # model_json_schema is the correct method for pydantic V2+
        json_schema = json.dumps(LogAnalysis.model_json_schema(), indent=2)

        # 3. Fill the Prompt Template
        final_prompt = self.prompt_template.format(
            log_type=log_type, 
            stress_prompt="", 
            logs=logs_text,
            model_schema=json_schema
        )

        try:
            print(f"[LLM Service] Sending request to OpenRouter (Model: {self.model_name}) for {log_type}...")

            # 4. Call the API (limit max tokens to avoid billing/credit 402 errors)
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a senior security analyst specializing in {log_type}. You must output valid JSON only, strictly following the provided schema. Do not include markdown formatting or any text outside the JSON object."
                    },
                    {
                        "role": "user",
                        "content": final_prompt
                    }
                ],
                temperature=0.1,
                max_tokens=LLM_MAX_TOKENS,
                response_format={"type": "json_object"}
            )

            # 5. Parse Response
            raw_content = response.choices[0].message.content
            print("[LLM Service] Received response.")

            # 6. Clean and Validate
            # Attempt to clean potential markdown wrappers added by the model
            if "```json" in raw_content:
                raw_content = raw_content.split("```json")[1].split("```")[0].strip()
            elif "```" in raw_content:
                raw_content = raw_content.split("```")[1].strip()

            # Attempt to parse the response
            try:
                analysis_data = LogAnalysis.model_validate_json(raw_content)
            except Exception as parse_err:
                # Check if this is a truncation error (EOF while parsing)
                is_truncation_error = "EOF while parsing" in str(parse_err) or "json_invalid" in str(parse_err)
                
                if is_truncation_error and retry_count < 2:
                    # RETRY: Response was truncated, try again with fewer logs
                    print(f"[LLM Service] Detected truncated response. Retrying with fewer logs (attempt {retry_count + 1})...")
                    return self.analyze_logs(logs, log_type, retry_count=retry_count + 1)
                
                # If parsing fails, try to handle common malformations
                # (e.g., LLM returned a list of events instead of a LogAnalysis object)
                try:
                    parsed = json.loads(raw_content)
                    # If it's a list, assume it's a list of events and wrap it
                    if isinstance(parsed, list):
                        analysis_data = LogAnalysis(
                            summary="Analysis results",
                            observations=["Model returned a list of events which has been converted to LogAnalysis format"],
                            events=[WebSecurityEvent.model_validate(e) if isinstance(e, dict) else e for e in parsed],
                            highest_severity=SeverityLevel.INFO
                        )
                    else:
                        raise parse_err
                except Exception:
                    # Last resort: try to salvage partial JSON if still truncated
                    if is_truncation_error:
                        analysis_data = self._salvage_incomplete_json(raw_content)
                    else:
                        raise parse_err
            
            # Calculate and set requires_immediate_attention flag
            # Checks if any event has a CRITICAL or HIGH severity
            if any(e.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for e in analysis_data.events):
                 analysis_data.requires_immediate_attention = True

            return analysis_data

        except Exception as e:
            err_text = str(e)
            # Don't print recursive error messages on retries
            if retry_count == 0:
                print(f"[LLM Service] API or Validation Error: {type(e).__name__}: {err_text}")

            # Provide actionable message for 402 (credits / max_tokens) errors
            observations = ["Check API Key and Model Name in config.py", "Check Internet Connection", "The model might have returned invalid JSON."]
            if '402' in err_text or 'credits' in err_text.lower() or 'max_tokens' in err_text.lower():
                observations.insert(0, "LLM request failed due to billing/credit or token limits. Consider lowering `LLM_MAX_TOKENS` in src/config.py or using a smaller model.")

            # If a fallback model is configured, provide guidance but do not auto-switch silently.

            if LLM_FALLBACK_MODEL_NAME:
                observations.append(f"A fallback model is configured: {LLM_FALLBACK_MODEL_NAME}. You may set `LLM_MODEL_NAME` to this value in src/config.py to try it.")

            # Only return error on final retry attempt
            return LogAnalysis(
                summary=f"Analysis Failed due to API/Validation Error: {type(e).__name__}",
                observations=observations,
                highest_severity=SeverityLevel.INFO
            )
    
    def _salvage_incomplete_json(self, incomplete_json: str) -> LogAnalysis:
        """
        Attempts to salvage a LogAnalysis from incomplete/truncated JSON response.
        Closes unclosed structures and provides best-effort parsing.
        """
        try:
            # Try to find the last complete structural element
            # Count braces to determine if we're in the middle of a structure
            open_braces = incomplete_json.count('{')
            close_braces = incomplete_json.count('}')
            
            # Add closing braces if needed
            repaired = incomplete_json
            if open_braces > close_braces:
                repaired += '}' * (open_braces - close_braces)
            
            # Try parsing the repaired JSON
            parsed = json.loads(repaired)
            
            # Create a LogAnalysis with whatever we could recover
            analysis_data = LogAnalysis(
                summary=parsed.get("summary", "Partial analysis (truncated response)"),
                observations=parsed.get("observations", ["Response was truncated but partial analysis recovered"]),
                planning=parsed.get("planning", []),
                events=[
                    WebSecurityEvent.model_validate(e) 
                    for e in parsed.get("events", [])
                    if isinstance(e, dict)
                ],
                traffic_patterns=[
                    WebTrafficPattern.model_validate(p)
                    for p in parsed.get("traffic_patterns", [])
                    if isinstance(p, dict)
                ],
                highest_severity=SeverityLevel.MEDIUM,
                requires_immediate_attention=False
            )
            
            print(f"[LLM Service] Successfully salvaged partial JSON response")
            return analysis_data
        except Exception as salvage_err:
            print(f"[LLM Service] Could not salvage truncated response: {salvage_err}")
            # Return a minimal valid response
            return LogAnalysis(
                summary="Analysis failed due to incomplete response",
                observations=[
                    "The LLM response was truncated and could not be recovered.",
                    "Try reducing the log limit or checking your LLM token allocation."
                ],
                highest_severity=SeverityLevel.INFO
            )

    # --- OPTIONAL: Image Analysis Method (If needed later) ---
    def analyze_image(self, image_url: str, prompt: str = "What is in this image?") -> str:
        # Implementation remains the same
        try:
            try:
                from config import LLM_VISION_MODEL_NAME
                vision_model = LLM_VISION_MODEL_NAME
            except ImportError:
                vision_model = self.model_name

            print(f"[LLM Service] Analyzing image: {image_url}")
            response = self.client.chat.completions.create(
                model=vision_model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": image_url}}
                        ]
                    }
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error analyzing image: {str(e)}"


# ==============================================================================
# 3. Service Singleton - EXPORTED
# ==============================================================================

class LLMService:
    _instance = None
    
    def __new__(cls):
        if not cls._instance:
            cls._instance = super(LLMService, cls).__new__(cls)
            # Initialize the analyzer instance once
            cls._instance.analyzer = STRESSED()
        return cls._instance

    def get_analyzer(self):
        """Returns the STRESSED instance which contains the LLM client."""
        return self.analyzer

def get_llm_service():
    """
    Public accessor function for the LLMService singleton.
    This is what CoreLogic imports and calls.
    """
    return LLMService()