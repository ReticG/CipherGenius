"""Requirement parser for natural language processing"""

import json
import re
from typing import Optional

from cipher_genius.models.requirement import (
    Requirement,
    ParsedRequirement,
    SecurityRequirement,
    PerformanceConstraint,
    TargetPlatform,
    SchemeType,
    PlatformType,
    ResourceLevel,
)
from cipher_genius.core.llm_interface import get_llm_interface
from cipher_genius.utils.logger import get_logger

logger = get_logger(__name__)


class RequirementParser:
    """Parse natural language requirements into structured format"""

    def __init__(self, llm_provider: Optional[str] = None):
        self.llm = get_llm_interface(llm_provider)

    def parse(self, description: str) -> ParsedRequirement:
        """Parse natural language description into structured requirement"""

        system_prompt = """You are an expert cryptographer and requirements analyst.
Your task is to parse natural language descriptions of cryptographic requirements
into structured technical specifications.

Extract the following information:
1. Scheme type (encryption, authenticated_encryption, signature, etc.)
2. Target platform (iot_device, mobile, server, etc.)
3. Resource level (ultra_lightweight, lightweight, moderate, high_performance)
4. Security level in bits (e.g., 128, 256)
5. Specific threats to defend against
6. Performance constraints (latency, memory, throughput, power)
7. Additional features or requirements

Be precise and conservative in your interpretations. If something is ambiguous,
note it in the ambiguities field and make a reasonable assumption."""

        user_prompt = f"""Parse this cryptographic requirement:

"{description}"

Respond with a JSON object containing:
{{
  "scheme_type": "one of: encryption, authenticated_encryption, signature, key_exchange, hash, mac, key_derivation, random_number_generation",
  "target_platform": {{
    "type": "one of: iot_device, mobile, desktop, server, embedded, cloud, web",
    "resource_level": "one of: ultra_lightweight, lightweight, moderate, high_performance",
    "details": {{}}
  }},
  "security": {{
    "security_level": 128,
    "threats": ["list of threats"],
    "properties": ["list of security properties like IND-CCA2"],
    "quantum_resistant": false
  }},
  "performance": {{
    "max_latency": "e.g., 10ms or null",
    "min_throughput": "e.g., 10KB/s or null",
    "max_memory": "e.g., 2KB or null",
    "max_power": "e.g., low or null",
    "max_code_size": "e.g., 4KB or null"
  }},
  "additional_features": ["list of features"],
  "preferences": {{}},
  "confidence": 0.9,
  "ambiguities": ["list of unclear aspects"],
  "assumptions": ["list of assumptions made"]
}}"""

        try:
            response = self.llm.generate_json(user_prompt, system_prompt, temperature=0.3)

            # Extract confidence and metadata
            confidence = response.get("confidence", 0.8)
            ambiguities = response.get("ambiguities", [])
            assumptions = response.get("assumptions", [])

            # Clean and normalize threat values
            security_data = response.get("security", {})
            if "threats" in security_data:
                security_data["threats"] = self._normalize_threats(security_data["threats"])

            # Build Requirement object
            requirement = Requirement(
                description=description,
                scheme_type=SchemeType(response["scheme_type"]),
                target_platform=TargetPlatform(
                    type=PlatformType(response["target_platform"]["type"]),
                    resource_level=ResourceLevel(response["target_platform"]["resource_level"]),
                    details=response["target_platform"].get("details", {}),
                ),
                security=SecurityRequirement(**security_data),
                performance=PerformanceConstraint(**response.get("performance", {})),
                additional_features=response.get("additional_features", []),
                preferences=response.get("preferences", {}),
            )

            return ParsedRequirement(
                requirement=requirement,
                confidence=confidence,
                ambiguities=ambiguities,
                assumptions=assumptions,
            )

        except Exception as e:
            # Fallback to basic parsing on error
            logger.error(f"Error parsing requirements: {e}")
            return self._fallback_parse(description)

    def _normalize_threats(self, threats: list) -> list:
        """Normalize threat strings to match ThreatType enum values"""
        # Mapping from LLM output variations to enum values
        threat_map = {
            "eavesdropping": "eavesdropping",
            "tampering": "tampering",
            "data tampering": "tampering",
            "message tampering": "tampering",
            "replay": "replay",
            "replay attack": "replay",
            "replay attacks": "replay",
            "forgery": "forgery",
            "message forgery": "forgery",
            "man-in-the-middle": "man_in_the_middle",
            "man in the middle": "man_in_the_middle",
            "man-in-the-middle attack": "man_in_the_middle",
            "man-in-the-middle attacks": "man_in_the_middle",
            "mitm": "man_in_the_middle",
            "side-channel": "side_channel",
            "side channel": "side_channel",
            "side-channel attack": "side_channel",
            "side-channel attacks": "side_channel",
            "quantum": "quantum",
            "quantum attack": "quantum",
            "quantum attacks": "quantum",
        }

        normalized = []
        for threat in threats:
            threat_lower = threat.lower().strip()
            if threat_lower in threat_map:
                normalized.append(threat_map[threat_lower])
            else:
                # Try to find a partial match
                for key, value in threat_map.items():
                    if key in threat_lower or threat_lower in key:
                        normalized.append(value)
                        break
                else:
                    # If no match found, skip this threat
                    logger.debug(f"Unknown threat type: {threat}, skipping")

        return normalized

    def _fallback_parse(self, description: str) -> ParsedRequirement:
        """Fallback parser with basic heuristics"""

        # Default values
        scheme_type = SchemeType.ENCRYPTION
        platform_type = PlatformType.SERVER
        resource_level = ResourceLevel.MODERATE
        security_level = 128

        # Simple keyword matching
        desc_lower = description.lower()

        # Detect scheme type
        if "authenticated encryption" in desc_lower or "aead" in desc_lower:
            scheme_type = SchemeType.AUTHENTICATED_ENCRYPTION
        elif "signature" in desc_lower or "sign" in desc_lower:
            scheme_type = SchemeType.SIGNATURE
        elif "key exchange" in desc_lower:
            scheme_type = SchemeType.KEY_EXCHANGE
        elif "hash" in desc_lower:
            scheme_type = SchemeType.HASH
        elif "mac" in desc_lower:
            scheme_type = SchemeType.MAC

        # Detect platform
        if "iot" in desc_lower or "embedded" in desc_lower:
            platform_type = PlatformType.IOT_DEVICE
            resource_level = ResourceLevel.LIGHTWEIGHT
        elif "mobile" in desc_lower:
            platform_type = PlatformType.MOBILE
        elif "cloud" in desc_lower or "server" in desc_lower:
            platform_type = PlatformType.SERVER
            resource_level = ResourceLevel.HIGH_PERFORMANCE

        # Detect security level (prioritize explicit security mentions over algorithm names)
        # Check for explicit security level statements first
        if "128-bit security" in desc_lower or "128 bit security" in desc_lower or "with 128-bit" in desc_lower:
            security_level = 128
        elif "256-bit security" in desc_lower or "256 bit security" in desc_lower or "with 256-bit" in desc_lower:
            security_level = 256
        # Fall back to looking for bit sizes, but avoid algorithm names
        elif "128-bit" in desc_lower and "sha-" not in desc_lower:
            security_level = 128
        elif "256-bit" in desc_lower and "sha-256" not in desc_lower and "aes-256" not in desc_lower:
            security_level = 256
        # Lastly, check for bare numbers (least reliable)
        elif re.search(r'\b128\b', description):
            security_level = 128
        elif re.search(r'\b256\b', description) and "sha-256" not in desc_lower:
            security_level = 256

        requirement = Requirement(
            description=description,
            scheme_type=scheme_type,
            target_platform=TargetPlatform(
                type=platform_type,
                resource_level=resource_level,
            ),
            security=SecurityRequirement(security_level=security_level),
        )

        return ParsedRequirement(
            requirement=requirement,
            confidence=0.5,
            ambiguities=["Fallback parser used - please review"],
            assumptions=["Default values used for unspecified parameters"],
        )

    def validate(self, requirement: Requirement) -> tuple[bool, list[str]]:
        """Validate a requirement for consistency and completeness"""
        issues = []

        # Check security level is reasonable
        if requirement.security.security_level not in [80, 112, 128, 192, 256]:
            issues.append(f"Unusual security level: {requirement.security.security_level}")

        # Check for contradictions
        if (requirement.target_platform.resource_level == ResourceLevel.ULTRA_LIGHTWEIGHT
            and requirement.security.security_level > 128):
            issues.append("Ultra-lightweight devices may struggle with >128-bit security")

        # Check performance constraints are reasonable
        perf = requirement.performance
        if perf.max_memory and "MB" in perf.max_memory:
            if requirement.target_platform.type == PlatformType.IOT_DEVICE:
                issues.append("IoT devices typically have KB, not MB of RAM")

        return len(issues) == 0, issues
