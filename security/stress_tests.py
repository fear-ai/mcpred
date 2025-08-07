"""
Performance and DoS resistance testing.
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional
import statistics

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.exceptions import SecurityTestError
from core.transports import TransportFactory, SecTransport


logger = logging.getLogger(__name__)


class StressTestResult:
    """Result of a stress test."""
    
    def __init__(self, test_type: str, success: bool, metrics: Dict[str, Any]):
        self.test_type = test_type
        self.success = success
        self.metrics = metrics
        self.timestamp = time.time()
        self.severity = self._calculate_severity()
    
    def _calculate_severity(self) -> str:
        """Calculate severity based on test results."""
        if not self.success:
            return "info"
        
        # Successful stress test indicates potential DoS vulnerability
        if "server_crash" in self.metrics or "connection_refused" in self.metrics:
            return "high"
        elif "performance_degradation" in self.metrics:
            return "medium"
        elif "resource_exhaustion" in self.metrics:
            return "medium"
        else:
            return "low"


class PerformanceMetrics:
    """Container for performance test results."""
    
    def __init__(self):
        self.connection_limit = 0
        self.max_concurrent_connections = 0
        self.average_response_time = 0.0
        self.median_response_time = 0.0
        self.p95_response_time = 0.0
        self.error_rate = 0.0
        self.throughput = 0.0  # requests per second
        self.memory_usage = {}
        self.cpu_usage = {}
        self.connection_errors = 0
        self.timeout_errors = 0
        self.server_errors = 0
        self.issues: List[Dict[str, Any]] = []
    
    def calculate_derived_metrics(self, response_times: List[float], total_requests: int, test_duration: float):
        """Calculate derived metrics from raw data."""
        if response_times:
            self.average_response_time = statistics.mean(response_times)
            self.median_response_time = statistics.median(response_times)
            self.p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        
        if test_duration > 0:
            self.throughput = total_requests / test_duration
        
        total_errors = self.connection_errors + self.timeout_errors + self.server_errors
        if total_requests > 0:
            self.error_rate = total_errors / total_requests
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "connection_limit": self.connection_limit,
            "max_concurrent_connections": self.max_concurrent_connections,
            "average_response_time": self.average_response_time,
            "median_response_time": self.median_response_time,
            "p95_response_time": self.p95_response_time,
            "error_rate": self.error_rate,
            "throughput": self.throughput,
            "connection_errors": self.connection_errors,
            "timeout_errors": self.timeout_errors,
            "server_errors": self.server_errors,
            "memory_usage": self.memory_usage,
            "cpu_usage": self.cpu_usage,
            "issues": self.issues,
        }


class StressTester:
    """Performance and DoS resistance testing."""
    
    def __init__(self, security_config: Optional[Dict[str, Any]] = None):
        self.security_config = security_config or {}
        self.test_results: List[StressTestResult] = []
        self.performance_metrics = PerformanceMetrics()
    
    async def test_connection_limits(self, target: str, transport_type: str) -> StressTestResult:
        """Test maximum concurrent connections."""
        logger.info("Testing connection limits")
        
        max_connections = self.security_config.get("max_concurrent_connections", 100)
        connection_timeout = self.security_config.get("connect_timeout", 5)
        
        metrics = {
            "test_description": "Connection limit testing",
            "max_attempted": max_connections,
            "successful_connections": 0,
            "connection_errors": 0,
            "final_connection_limit": 0
        }
        
        try:
            successful_connections = 0
            transports = []
            
            for conn_count in range(1, max_connections + 1, 5):  # Test in increments of 5
                batch_transports = []
                batch_successful = 0
                
                # Try to create a batch of connections
                for i in range(5):
                    if conn_count + i > max_connections:
                        break
                    
                    try:
                        transport = TransportFactory.create_transport(
                            transport_type, 
                            target,
                            self.security_config
                        )
                        
                        # Try to connect with timeout
                        connection_task = asyncio.create_task(
                            transport.connect_with_monitoring().__aenter__()
                        )
                        
                        try:
                            session = await asyncio.wait_for(connection_task, timeout=connection_timeout)
                            batch_transports.append((transport, session))
                            batch_successful += 1
                        except asyncio.TimeoutError:
                            metrics["connection_errors"] += 1
                            break
                        except Exception as e:
                            metrics["connection_errors"] += 1
                            logger.debug(f"Connection failed: {e}")
                            break
                    
                    except Exception as e:
                        metrics["connection_errors"] += 1
                        logger.debug(f"Transport creation failed: {e}")
                        break
                
                if batch_successful == 0:
                    # No more connections possible
                    break
                
                successful_connections += batch_successful
                transports.extend(batch_transports)
                
                # Small delay between batches
                await asyncio.sleep(0.1)
            
            metrics["successful_connections"] = successful_connections
            metrics["final_connection_limit"] = successful_connections
            self.performance_metrics.connection_limit = successful_connections
            self.performance_metrics.max_concurrent_connections = successful_connections
            
            # Clean up connections
            for transport, session in transports:
                try:
                    await transport.disconnect()
                except:
                    pass
            
            # Determine if this indicates a vulnerability
            success = False
            if successful_connections == 0:
                success = True
                metrics["vulnerability_type"] = "connection_refused"
                metrics["description"] = "Server refuses all connections"
            elif successful_connections > 1000:  # Arbitrary high limit
                success = True
                metrics["vulnerability_type"] = "no_connection_limits"
                metrics["description"] = f"Server allows unlimited connections ({successful_connections}+)"
            
            result = StressTestResult("connection_limits", success, metrics)
            self.test_results.append(result)
            
            logger.info(f"Connection limit test completed. Max connections: {successful_connections}")
            return result
            
        except Exception as e:
            error_metrics = dict(metrics)
            error_metrics["error"] = str(e)
            error_result = StressTestResult("connection_limits", False, error_metrics)
            self.test_results.append(error_result)
            raise SecurityTestError("stress_test", f"Connection limit testing failed: {str(e)}")
    
    async def test_resource_exhaustion(self, target: str, transport_type: str) -> StressTestResult:
        """Test server resource exhaustion resistance."""
        logger.info("Testing resource exhaustion resistance")
        
        test_duration = self.security_config.get("stress_test_duration", 30)  # 30 seconds
        request_rate = self.security_config.get("request_rate", 10)  # requests per second
        
        metrics = {
            "test_description": "Resource exhaustion testing",
            "test_duration": test_duration,
            "target_rate": request_rate,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "response_times": [],
            "memory_usage": []
        }
        
        try:
            start_time = time.time()
            end_time = start_time + test_duration
            
            transport = TransportFactory.create_transport(transport_type, target, self.security_config)
            
            async with transport.connect_with_monitoring() as session:
                session_manager = None
                try:
                    from core.session import SecSessionManager
                    session_manager = SecSessionManager(session)
                    await session_manager.initialize()
                except Exception as e:
                    logger.warning(f"Failed to initialize session manager: {e}")
                
                while time.time() < end_time:
                    batch_start = time.time()
                    
                    # Send batch of requests
                    tasks = []
                    for _ in range(request_rate):
                        if session_manager:
                            task = self._make_test_request(session_manager)
                        else:
                            task = self._make_raw_request(transport)
                        tasks.append(task)
                    
                    # Execute batch
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Process results
                    for result in batch_results:
                        metrics["total_requests"] += 1
                        if isinstance(result, Exception):
                            metrics["failed_requests"] += 1
                        else:
                            metrics["successful_requests"] += 1
                            if isinstance(result, dict) and "response_time" in result:
                                metrics["response_times"].append(result["response_time"])
                    
                    # Wait for next batch (rate limiting)
                    batch_duration = time.time() - batch_start
                    sleep_time = max(0, 1.0 - batch_duration)  # 1 second per batch
                    await asyncio.sleep(sleep_time)
            
            # Calculate final metrics
            total_duration = time.time() - start_time
            if metrics["response_times"]:
                self.performance_metrics.calculate_derived_metrics(
                    metrics["response_times"],
                    metrics["total_requests"], 
                    total_duration
                )
                metrics["average_response_time"] = self.performance_metrics.average_response_time
                metrics["throughput"] = self.performance_metrics.throughput
                metrics["error_rate"] = self.performance_metrics.error_rate
            
            # Determine if this indicates a vulnerability
            success = False
            if metrics["failed_requests"] > metrics["successful_requests"] * 0.5:  # >50% failure rate
                success = True
                metrics["vulnerability_type"] = "service_degradation"
                metrics["description"] = f"High failure rate: {metrics['error_rate']:.2%}"
            elif self.performance_metrics.average_response_time > 10.0:  # >10 second response times
                success = True
                metrics["vulnerability_type"] = "performance_degradation"
                metrics["description"] = f"Slow response times: {self.performance_metrics.average_response_time:.2f}s average"
            
            result = StressTestResult("resource_exhaustion", success, metrics)
            self.test_results.append(result)
            
            logger.info(f"Resource exhaustion test completed. {metrics['total_requests']} requests in {total_duration:.1f}s")
            return result
            
        except Exception as e:
            error_metrics = dict(metrics)
            error_metrics["error"] = str(e)
            error_result = StressTestResult("resource_exhaustion", False, error_metrics)
            self.test_results.append(error_result)
            raise SecurityTestError("stress_test", f"Resource exhaustion testing failed: {str(e)}")
    
    async def test_slowloris_attack(self, target: str, transport_type: str) -> StressTestResult:
        """Test resistance to slow connection attacks."""
        logger.info("Testing Slowloris attack resistance")
        
        max_slow_connections = self.security_config.get("max_slow_connections", 50)
        slow_timeout = self.security_config.get("slow_timeout", 60)  # 1 minute
        
        metrics = {
            "test_description": "Slowloris attack simulation",
            "max_slow_connections": max_slow_connections,
            "active_slow_connections": 0,
            "server_timeout": 0,
            "connection_drops": 0
        }
        
        try:
            slow_connections = []
            
            for i in range(max_slow_connections):
                try:
                    transport = TransportFactory.create_transport(transport_type, target, self.security_config)
                    
                    # Start connection but don't complete handshake
                    connection_task = asyncio.create_task(
                        self._create_slow_connection(transport, slow_timeout)
                    )
                    slow_connections.append(connection_task)
                    metrics["active_slow_connections"] += 1
                    
                    # Small delay between connection attempts
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    logger.debug(f"Slow connection {i} failed: {e}")
                    break
            
            # Wait and monitor slow connections
            if slow_connections:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*slow_connections, return_exceptions=True),
                        timeout=slow_timeout
                    )
                except asyncio.TimeoutError:
                    # Connections timed out - good server behavior
                    metrics["server_timeout"] = len(slow_connections)
            
            # Cancel remaining connections
            for task in slow_connections:
                if not task.done():
                    task.cancel()
            
            # Determine if this indicates a vulnerability
            success = False
            if metrics["active_slow_connections"] > 20 and metrics["server_timeout"] == 0:
                success = True
                metrics["vulnerability_type"] = "slowloris_vulnerable"
                metrics["description"] = f"Server doesn't handle slow connections properly ({metrics['active_slow_connections']} slow connections maintained)"
            
            result = StressTestResult("slowloris", success, metrics)
            self.test_results.append(result)
            
            logger.info(f"Slowloris test completed. {metrics['active_slow_connections']} slow connections created")
            return result
            
        except Exception as e:
            error_metrics = dict(metrics)
            error_metrics["error"] = str(e)
            error_result = StressTestResult("slowloris", False, error_metrics)
            self.test_results.append(error_result)
            raise SecurityTestError("stress_test", f"Slowloris testing failed: {str(e)}")
    
    async def test_memory_exhaustion(self, target: str, transport_type: str) -> StressTestResult:
        """Test memory exhaustion via large payloads."""
        logger.info("Testing memory exhaustion resistance")
        
        max_payload_size = self.security_config.get("max_payload_size", 10 * 1024 * 1024)  # 10MB
        payload_count = self.security_config.get("memory_test_payloads", 10)
        
        metrics = {
            "test_description": "Memory exhaustion testing",
            "max_payload_size": max_payload_size,
            "payload_count": payload_count,
            "successful_large_requests": 0,
            "memory_errors": 0,
            "server_crashes": 0
        }
        
        try:
            transport = TransportFactory.create_transport(transport_type, target, self.security_config)
            
            # Create progressively larger payloads
            for i in range(payload_count):
                payload_size = max_payload_size // payload_count * (i + 1)
                large_payload = self._create_large_payload(payload_size)
                
                try:
                    response = await transport.inject_malformed_request(large_payload)
                    metrics["successful_large_requests"] += 1
                    
                    # Check if server handled large payload appropriately
                    if self._indicates_memory_issue(response):
                        metrics["memory_errors"] += 1
                
                except Exception as e:
                    error_str = str(e).lower()
                    if any(mem_error in error_str for mem_error in ["memory", "out of memory", "oom"]):
                        metrics["memory_errors"] += 1
                    elif any(crash_indicator in error_str for crash_indicator in ["connection reset", "connection aborted"]):
                        metrics["server_crashes"] += 1
                
                # Small delay between large requests
                await asyncio.sleep(1)
            
            # Determine if this indicates a vulnerability
            success = False
            if metrics["memory_errors"] > 0:
                success = True
                metrics["vulnerability_type"] = "memory_exhaustion"
                metrics["description"] = f"Server showed memory exhaustion symptoms ({metrics['memory_errors']} instances)"
            elif metrics["server_crashes"] > 0:
                success = True
                metrics["vulnerability_type"] = "server_crash"
                metrics["description"] = f"Server crashed handling large payloads ({metrics['server_crashes']} crashes)"
            elif metrics["successful_large_requests"] == payload_count:
                # Server accepted all large payloads - potential DoS vector
                success = True
                metrics["vulnerability_type"] = "large_payload_acceptance"
                metrics["description"] = f"Server accepts large payloads without limits (up to {max_payload_size} bytes)"
            
            result = StressTestResult("memory_exhaustion", success, metrics)
            self.test_results.append(result)
            
            logger.info(f"Memory exhaustion test completed. {metrics['successful_large_requests']}/{payload_count} large payloads accepted")
            return result
            
        except Exception as e:
            error_metrics = dict(metrics)
            error_metrics["error"] = str(e)
            error_result = StressTestResult("memory_exhaustion", False, error_metrics)
            self.test_results.append(error_result)
            raise SecurityTestError("stress_test", f"Memory exhaustion testing failed: {str(e)}")
    
    async def _make_test_request(self, session_manager) -> Dict[str, Any]:
        """Make a test request and measure response time."""
        start_time = time.time()
        try:
            await session_manager.list_tools()
            response_time = time.time() - start_time
            return {"success": True, "response_time": response_time}
        except Exception as e:
            response_time = time.time() - start_time
            return {"success": False, "response_time": response_time, "error": str(e)}
    
    async def _make_raw_request(self, transport: SecTransport) -> Dict[str, Any]:
        """Make a raw request via transport and measure response time."""
        start_time = time.time()
        try:
            response = await transport.inject_malformed_request({
                "jsonrpc": "2.0",
                "method": "ping", 
                "id": 1
            })
            response_time = time.time() - start_time
            return {"success": True, "response_time": response_time, "response": response}
        except Exception as e:
            response_time = time.time() - start_time
            return {"success": False, "response_time": response_time, "error": str(e)}
    
    async def _create_slow_connection(self, transport: SecTransport, timeout: float) -> None:
        """Create a slow/partial connection for Slowloris testing."""
        try:
            # This is a simplified version - real Slowloris would create partial HTTP connections
            # For MCP, we simulate by creating connection but sending minimal data very slowly
            
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    # Send minimal data very slowly
                    await transport.inject_malformed_request({"partial": "data"})
                    await asyncio.sleep(5)  # Long delay between partial requests
                except:
                    break
                    
        except Exception:
            pass
    
    def _create_large_payload(self, size: int) -> Dict[str, Any]:
        """Create a large payload for memory exhaustion testing."""
        # Create large string payload
        large_string = "A" * (size // 2)
        large_array = list(range(min(size // 100, 10000)))
        
        return {
            "jsonrpc": "2.0",
            "method": "memory_test",
            "params": {
                "large_string": large_string,
                "large_array": large_array,
                "nested_data": {
                    f"key_{i}": f"value_{i}" * 100
                    for i in range(min(size // 1000, 1000))
                }
            },
            "id": 1
        }
    
    def _indicates_memory_issue(self, response: Any) -> bool:
        """Check if response indicates memory issues."""
        if not response:
            return False
        
        response_str = str(response).lower()
        memory_indicators = [
            "out of memory", "memory exhausted", "memory limit",
            "heap", "garbage collection", "oom", "memory error"
        ]
        
        return any(indicator in response_str for indicator in memory_indicators)
    
    def get_vulnerabilities(self) -> List[StressTestResult]:
        """Get only stress test results that indicate vulnerabilities."""
        return [result for result in self.test_results if result.success]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of stress testing results."""
        vulnerabilities = self.get_vulnerabilities()
        
        return {
            "total_tests": len(self.test_results),
            "vulnerabilities_found": len(vulnerabilities),
            "performance_metrics": self.performance_metrics.to_dict(),
            "vulnerability_types": [v.metrics.get("vulnerability_type") for v in vulnerabilities],
            "severity_breakdown": {
                "high": len([v for v in vulnerabilities if v.severity == "high"]),
                "medium": len([v for v in vulnerabilities if v.severity == "medium"]),
                "low": len([v for v in vulnerabilities if v.severity == "low"])
            },
            "test_types_executed": list(set(result.test_type for result in self.test_results))
        }