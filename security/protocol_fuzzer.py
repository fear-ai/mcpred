"""
JSON-RPC protocol fuzzing and malformation testing.
"""

import asyncio
import json
import logging
import random
import string
from typing import Dict, List, Any, Optional, Union
import time

from ..core.exceptions import ProtocolFuzzError
from ..core.transports import SecTransport


logger = logging.getLogger(__name__)


class FuzzPayload:
    """Container for a fuzz test payload."""
    
    def __init__(self, payload: Dict[str, Any], description: str, category: str):
        self.payload = payload
        self.description = description
        self.category = category
        self.timestamp = time.time()


class FuzzResult:
    """Result of a protocol fuzz test."""
    
    def __init__(self, payload: FuzzPayload, response: Any, success: bool, **kwargs):
        self.payload = payload
        self.response = response
        self.success = success  # True if the fuzz revealed a vulnerability
        self.details = kwargs
        self.timestamp = time.time()
        self.severity = self._calculate_severity()
    
    def _calculate_severity(self) -> str:
        """Calculate severity based on the type of fuzz success."""
        if not self.success:
            return "info"
        
        # Successful fuzz indicates potential vulnerability
        if "crash" in self.details or "error_500" in self.details:
            return "high"
        elif "malformed_accepted" in self.details:
            return "medium"
        elif "information_disclosure" in self.details:
            return "medium"
        else:
            return "low"


class ProtocolFuzzer:
    """JSON-RPC protocol fuzzing and malformation testing."""
    
    def __init__(self):
        self.fuzz_results: List[FuzzResult] = []
        self.payload_generators = [
            self._generate_malformed_json,
            self._generate_invalid_jsonrpc,
            self._generate_oversized_payloads,
            self._generate_type_confusion,
            self._generate_injection_payloads,
            self._generate_unicode_payloads,
            self._generate_null_payloads,
            self._generate_array_confusion
        ]
    
    async def fuzz_json_rpc(self, transport: SecTransport, fuzz_config: Dict[str, Any]) -> List[FuzzResult]:
        """Fuzz JSON-RPC requests with malformed data."""
        logger.info(f"Starting JSON-RPC fuzzing with {fuzz_config.get('request_count', 100)} requests")
        
        request_count = fuzz_config.get("request_count", 100)
        malformed_rate = fuzz_config.get("malformed_rate", 0.3)
        max_payload_size = fuzz_config.get("max_payload_size", 1024 * 1024)  # 1MB
        
        results = []
        malformed_count = int(request_count * malformed_rate)
        
        try:
            for i in range(malformed_count):
                # Generate fuzz payload
                generator = random.choice(self.payload_generators)
                fuzz_payload = generator(max_payload_size)
                
                try:
                    # Send malformed request
                    response = await transport.inject_malformed_request(fuzz_payload.payload)
                    
                    # Analyze response for vulnerabilities
                    success, details = self._analyze_fuzz_response(fuzz_payload, response)
                    
                    result = FuzzResult(fuzz_payload, response, success, **details)
                    results.append(result)
                    
                    if success:
                        logger.warning(f"Fuzz payload {i} revealed potential vulnerability: {fuzz_payload.description}")
                    
                except Exception as e:
                    # Server crash or unexpected error
                    result = FuzzResult(
                        fuzz_payload, 
                        str(e), 
                        True,  # Exception indicates vulnerability
                        crash=True,
                        error_type=type(e).__name__,
                        error_message=str(e)
                    )
                    results.append(result)
                    logger.error(f"Fuzz payload {i} caused server error: {e}")
                
                # Small delay to avoid overwhelming server
                await asyncio.sleep(0.01)
            
            self.fuzz_results.extend(results)
            logger.info(f"Fuzzing completed. Found {len([r for r in results if r.success])} potential vulnerabilities")
            return results
            
        except Exception as e:
            raise ProtocolFuzzError(f"Fuzzing operation failed: {str(e)}")
    
    async def test_schema_violations(self, transport: SecTransport) -> List[FuzzResult]:
        """Test schema validation bypass attempts."""
        logger.info("Testing schema validation bypass")
        
        results = []
        
        # Schema violation payloads
        schema_violation_payloads = [
            self._create_payload({"jsonrpc": "2.0"}, "Missing required method field", "schema_violation"),
            self._create_payload({"method": "test"}, "Missing jsonrpc version", "schema_violation"),
            self._create_payload({"jsonrpc": "1.0", "method": "test"}, "Invalid jsonrpc version", "schema_violation"),
            self._create_payload({"jsonrpc": "2.0", "method": "", "id": 1}, "Empty method name", "schema_violation"),
            self._create_payload({"jsonrpc": "2.0", "method": None, "id": 1}, "Null method", "schema_violation"),
            self._create_payload({"jsonrpc": "2.0", "method": 123, "id": 1}, "Non-string method", "schema_violation"),
            self._create_payload({"jsonrpc": "2.0", "method": "test", "params": "invalid", "id": 1}, "Invalid params type", "schema_violation"),
            self._create_payload({"jsonrpc": "2.0", "method": "test", "id": None}, "Null id", "schema_violation"),
        ]
        
        for payload in schema_violation_payloads:
            try:
                response = await transport.inject_malformed_request(payload.payload)
                success, details = self._analyze_schema_violation_response(payload, response)
                
                result = FuzzResult(payload, response, success, **details)
                results.append(result)
                
            except Exception as e:
                result = FuzzResult(
                    payload,
                    str(e),
                    True,
                    schema_violation_crash=True,
                    error=str(e)
                )
                results.append(result)
        
        self.fuzz_results.extend(results)
        return results
    
    def _generate_malformed_json(self, max_size: int) -> FuzzPayload:
        """Generate malformed JSON payloads."""
        malformed_jsons = [
            '{"jsonrpc": "2.0", "method": "test"',  # Unclosed brace
            '{"jsonrpc": "2.0", "method": "test", "id": }',  # Missing value
            '{"jsonrpc": "2.0", "method": "test", "id": 1,}',  # Trailing comma
            '{"jsonrpc": "2.0", "method": "test", "id": 1, "duplicate": 1, "duplicate": 2}',  # Duplicate keys
            '{"jsonrpc": "2.0", "method": "test", "id": 01}',  # Invalid number format
            '{"jsonrpc": "2.0", "method": "test", "params": [1,2,3,]}',  # Trailing comma in array
            '{jsonrpc: "2.0", method: "test"}',  # Unquoted keys
            '{"jsonrpc": "2.0", "method": "test", "id": 1e999999}',  # Invalid number
        ]
        
        payload = random.choice(malformed_jsons)
        
        # Ensure we don't exceed max size
        if len(payload) > max_size:
            payload = payload[:max_size]
        
        return FuzzPayload(
            {"_raw_json": payload},
            f"Malformed JSON: {payload[:50]}...",
            "malformed_json"
        )
    
    def _generate_invalid_jsonrpc(self, max_size: int) -> FuzzPayload:
        """Generate invalid JSON-RPC payloads."""
        invalid_payloads = [
            {"jsonrpc": "3.0", "method": "test", "id": 1},  # Future version
            {"jsonrpc": "1.0", "method": "test", "id": 1},  # Old version
            {"jsonrpc": 2.0, "method": "test", "id": 1},  # Numeric version
            {"jsonrpc": None, "method": "test", "id": 1},  # Null version
            {"version": "2.0", "method": "test", "id": 1},  # Wrong field name
            {"jsonrpc": "2.0", "method": 123, "id": 1},  # Numeric method
            {"jsonrpc": "2.0", "method": ["array", "method"], "id": 1},  # Array method
            {"jsonrpc": "2.0", "method": {"nested": "object"}, "id": 1},  # Object method
        ]
        
        payload = random.choice(invalid_payloads)
        return FuzzPayload(payload, f"Invalid JSON-RPC: {str(payload)}", "invalid_jsonrpc")
    
    def _generate_oversized_payloads(self, max_size: int) -> FuzzPayload:
        """Generate oversized payloads to test limits."""
        # Generate different types of large payloads
        large_string = "A" * min(max_size // 2, 100000)
        large_array = list(range(min(max_size // 100, 10000)))
        large_object = {f"key_{i}": f"value_{i}" for i in range(min(max_size // 200, 5000))}
        
        oversized_payloads = [
            {"jsonrpc": "2.0", "method": large_string, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "params": {"large_string": large_string}, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "params": large_array, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "params": large_object, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "id": large_string},
        ]
        
        payload = random.choice(oversized_payloads)
        return FuzzPayload(payload, f"Oversized payload: {len(str(payload))} bytes", "oversized")
    
    def _generate_type_confusion(self, max_size: int) -> FuzzPayload:
        """Generate type confusion payloads."""
        type_confusion_payloads = [
            {"jsonrpc": "2.0", "method": "test", "params": 123, "id": 1},  # Number instead of object/array
            {"jsonrpc": "2.0", "method": "test", "params": "string_params", "id": 1},  # String params
            {"jsonrpc": "2.0", "method": "test", "params": True, "id": 1},  # Boolean params
            {"jsonrpc": "2.0", "method": "test", "id": [1, 2, 3]},  # Array id
            {"jsonrpc": "2.0", "method": "test", "id": {"nested": "id"}},  # Object id
            {"jsonrpc": "2.0", "method": "test", "id": True},  # Boolean id
            {"jsonrpc": ["2.0"], "method": "test", "id": 1},  # Array version
            {"jsonrpc": "2.0", "method": "test", "params": None, "id": 1},  # Null params
        ]
        
        payload = random.choice(type_confusion_payloads)
        return FuzzPayload(payload, f"Type confusion: {str(payload)}", "type_confusion")
    
    def _generate_injection_payloads(self, max_size: int) -> FuzzPayload:
        """Generate potential injection payloads."""
        injection_strings = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "{{7*7}}",
            "${7*7}",
            "/../../../etc/passwd",
            "{{constructor.constructor('return process')().exit()}}",
            "__import__('os').system('id')",
            "eval('2+2')",
            "\x00\x01\x02\x03",  # Null bytes
            "\\u0000\\u0001",  # Unicode nulls
        ]
        
        injection_payload = random.choice(injection_strings)
        
        injection_payloads = [
            {"jsonrpc": "2.0", "method": injection_payload, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "params": {"injection": injection_payload}, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "params": [injection_payload], "id": 1},
            {"jsonrpc": "2.0", "method": "test", "id": injection_payload},
        ]
        
        payload = random.choice(injection_payloads)
        return FuzzPayload(payload, f"Injection payload: {injection_payload[:30]}...", "injection")
    
    def _generate_unicode_payloads(self, max_size: int) -> FuzzPayload:
        """Generate Unicode and encoding-related payloads."""
        unicode_strings = [
            "\\u0000\\u0001\\u0002",  # Control characters
            "\\uFFFE\\uFFFF",  # Invalid Unicode
            "\\uD800\\uDC00",  # Surrogate pairs
            "\\u202E",  # Right-to-left override
            "🔥💀🚨" * 100,  # Emoji spam
            "А" * 100,  # Cyrillic characters
            "𝕏" * 50,  # Mathematical symbols
            "\\x00\\x01\\x02",  # Raw bytes
        ]
        
        unicode_payload = random.choice(unicode_strings)
        
        unicode_payloads = [
            {"jsonrpc": "2.0", "method": unicode_payload, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "params": {"unicode": unicode_payload}, "id": 1},
            {"jsonrpc": unicode_payload, "method": "test", "id": 1},
        ]
        
        payload = random.choice(unicode_payloads)
        return FuzzPayload(payload, f"Unicode payload: {unicode_payload[:30]}...", "unicode")
    
    def _generate_null_payloads(self, max_size: int) -> FuzzPayload:
        """Generate null and undefined value payloads."""
        null_payloads = [
            None,
            {"jsonrpc": None, "method": "test", "id": 1},
            {"jsonrpc": "2.0", "method": None, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "params": None, "id": 1},
            {"jsonrpc": "2.0", "method": "test", "id": None},
            {},  # Empty object
            [],  # Empty array
            "",  # Empty string
        ]
        
        payload = random.choice(null_payloads)
        return FuzzPayload(payload, f"Null/empty payload: {str(payload)}", "null_empty")
    
    def _generate_array_confusion(self, max_size: int) -> FuzzPayload:
        """Generate array confusion payloads."""
        array_payloads = [
            [],  # Empty array
            [{"jsonrpc": "2.0", "method": "test", "id": 1}],  # Array with single request
            [
                {"jsonrpc": "2.0", "method": "test1", "id": 1},
                {"jsonrpc": "2.0", "method": "test2", "id": 2}
            ],  # Batch request
            [
                {"jsonrpc": "2.0", "method": "test", "id": 1},
                "invalid_request_in_batch"
            ],  # Mixed types in batch
            [None, None, None],  # Null requests in batch
        ]
        
        payload = random.choice(array_payloads)
        return FuzzPayload(payload, f"Array confusion: {str(payload)}", "array_confusion")
    
    def _create_payload(self, payload_dict: Dict[str, Any], description: str, category: str) -> FuzzPayload:
        """Create a FuzzPayload with the given parameters."""
        return FuzzPayload(payload_dict, description, category)
    
    def _analyze_fuzz_response(self, payload: FuzzPayload, response: Any) -> tuple[bool, Dict[str, Any]]:
        """Analyze fuzz response for potential vulnerabilities."""
        details = {}
        success = False
        
        if not response:
            return False, {"analysis": "No response received"}
        
        response_str = str(response).lower()
        
        # Check for server errors indicating vulnerability
        if any(error in response_str for error in ["500", "internal server error", "crash", "exception"]):
            success = True
            details["vulnerability_type"] = "server_error"
            details["description"] = "Server returned error, indicating potential vulnerability"
        
        # Check for malformed request acceptance
        if any(success_indicator in response_str for success_indicator in ["200", "success", "ok", "result"]):
            if payload.category in ["malformed_json", "invalid_jsonrpc", "schema_violation"]:
                success = True
                details["vulnerability_type"] = "malformed_accepted"
                details["description"] = "Server accepted malformed request"
        
        # Check for information disclosure
        if any(info_pattern in response_str for info_pattern in ["path", "file", "directory", "internal", "debug", "stack"]):
            success = True
            details["vulnerability_type"] = "information_disclosure" 
            details["description"] = "Response may contain sensitive information"
        
        # Check response size for potential DoS
        if isinstance(response, (str, dict)) and len(str(response)) > 1000000:  # 1MB
            success = True
            details["vulnerability_type"] = "resource_exhaustion"
            details["description"] = "Server returned unusually large response"
        
        return success, details
    
    def _analyze_schema_violation_response(self, payload: FuzzPayload, response: Any) -> tuple[bool, Dict[str, Any]]:
        """Analyze schema violation response for vulnerabilities."""
        details = {}
        success = False
        
        response_str = str(response).lower()
        
        # Schema violations should return proper error responses
        # If they return success, it's a vulnerability
        if any(success_indicator in response_str for success_indicator in ["200", "success", "result"]):
            success = True
            details["vulnerability_type"] = "schema_validation_bypass"
            details["description"] = "Server accepted request with schema violation"
        
        # Check for improper error handling
        if "500" in response_str or "crash" in response_str:
            success = True
            details["vulnerability_type"] = "improper_error_handling"
            details["description"] = "Schema violation caused server error"
        
        return success, details
    
    def get_vulnerabilities(self) -> List[FuzzResult]:
        """Get only fuzz results that indicate vulnerabilities."""
        return [result for result in self.fuzz_results if result.success]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of fuzzing results."""
        vulnerabilities = self.get_vulnerabilities()
        
        return {
            "total_tests": len(self.fuzz_results),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerability_categories": list(set(v.payload.category for v in vulnerabilities)),
            "severity_breakdown": {
                "high": len([v for v in vulnerabilities if v.severity == "high"]),
                "medium": len([v for v in vulnerabilities if v.severity == "medium"]),
                "low": len([v for v in vulnerabilities if v.severity == "low"])
            },
            "common_vulnerability_types": self._get_common_vulnerability_types(vulnerabilities)
        }
    
    def _get_common_vulnerability_types(self, vulnerabilities: List[FuzzResult]) -> Dict[str, int]:
        """Get counts of common vulnerability types."""
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.details.get("vulnerability_type", "unknown")
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        return vuln_types