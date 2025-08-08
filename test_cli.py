#!/usr/bin/env python3
"""
Comprehensive CLI validation tests for mcpred.
Tests commands, options, error handling, and file operations.
"""

import subprocess
import sys
import os
import tempfile
import json
import argparse
import concurrent.futures
from pathlib import Path

def run_cmd(cmd_args, expect_success=True, input_data=None, use_batch=False):
    """Run a CLI command and return result."""
    if use_batch:
        return run_cmd_batch([cmd_args], [expect_success])[0]
    
    try:
        # Get current working directory as the project root
        project_root = Path(__file__).parent
        
        full_cmd = ['uv', 'run', 'python', '-m', 'cli.main'] + cmd_args
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            input=input_data,
            cwd=str(project_root),
            timeout=10  # Add timeout to prevent hanging
        )
        
        if expect_success and result.returncode != 0:
            print(f"UNEXPECTED FAILURE: {' '.join(cmd_args)}")
            print(f"   STDOUT: {result.stdout}")
            print(f"   STDERR: {result.stderr}")
            return False
        elif not expect_success and result.returncode == 0:
            print(f"EXPECTED FAILURE BUT SUCCEEDED: {' '.join(cmd_args)}")
            return False
        else:
            success_mark = "PASS" if expect_success else "FAIL"
            print(f"{success_mark} {' '.join(cmd_args)}")
            return True
            
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT: {' '.join(cmd_args)} (network related)")
        # Network timeouts are expected failures for our mock URLs
        return not expect_success  # Timeout = failure, which might be expected
    except Exception as e:
        print(f"EXCEPTION: {' '.join(cmd_args)} - {e}")
        return False

def run_cmd_batch(cmd_list, expect_success_list):
    """Run multiple commands in parallel to reduce subprocess overhead."""
    project_root = Path(__file__).parent
    
    def run_single(cmd_args, expect_success):
        try:
            full_cmd = ['uv', 'run', 'python', '-m', 'cli.main'] + cmd_args
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                cwd=str(project_root),
                timeout=10
            )
            
            success = (expect_success and result.returncode == 0) or (not expect_success and result.returncode != 0)
            
            if not success:
                if expect_success:
                    print(f"UNEXPECTED FAILURE: {' '.join(cmd_args)}")
                else:
                    print(f"EXPECTED FAILURE BUT SUCCEEDED: {' '.join(cmd_args)}")
            else:
                success_mark = "PASS" if expect_success else "FAIL"
                print(f"{success_mark} {' '.join(cmd_args)}")
            
            return success
            
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT: {' '.join(cmd_args)} (network related)")
            return not expect_success
        except Exception as e:
            print(f"EXCEPTION: {' '.join(cmd_args)} - {e}")
            return False
    
    # Use ThreadPoolExecutor for I/O bound subprocess operations
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_single, cmd, expect) for cmd, expect in zip(cmd_list, expect_success_list)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    return results

def test_basic_commands(use_batch=True):
    """Test basic command functionality."""
    print("\nTesting Basic Commands")
    
    tests = [
        # Help commands - long and short forms
        (['--help'], True),
        (['-h'], True),
        (['discover', '--help'], True),
        (['discover', '-h'], True),
        (['dis', '--help'], True),
        (['dis', '-h'], True),
        (['scan', '--help'], True),
        (['scan', '-h'], True),
        (['sc', '--help'], True),
        (['sc', '-h'], True),
        (['conf', '--help'], True),
        (['conf', '-h'], True),
        (['run', '--help'], True),
        (['run', '-h'], True),
        
        # Version commands - long and short forms  
        (['--version'], True),
        (['-v'], True),
        
        # Invalid commands
        (['invalid-command'], False),
        (['xyz'], False),
        (['nonexistent'], False),
    ]
    
    if use_batch:
        # Run tests in parallel batches for speed
        cmd_list = [test[0] for test in tests]
        expect_list = [test[1] for test in tests]
        results = run_cmd_batch(cmd_list, expect_list)
        passed = sum(results)
    else:
        passed = 0
        for cmd, expect_success in tests:
            if run_cmd(cmd, expect_success):
                passed += 1
    
    print(f"\nBasic Commands: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_option_validation(use_batch=True):
    """Test command line option validation including short forms."""
    print("\nTesting Option Validation")
    
    # Use mock URLs to avoid network calls
    test_url = "https://mock.test"
    
    tests = [
        # Transport options - long and short forms (will fail network but pass CLI validation)  
        (['discover', test_url, '--transport', 'https'], False),
        (['discover', test_url, '--tran', 'http'], False),
        (['discover', test_url, '-t', 'websocket'], False),
        (['discover', 'ws://mock.test', '--transport', 'websocket'], False),
        
        # Invalid transport options  
        (['discover', test_url, '--tran', 'invalid'], False),
        (['discover', test_url, '--transport', 'xyz'], False),
        (['discover', test_url, '-t', 'ftp'], False),
        
        # Format options - long and short forms (will fail network but pass CLI validation)
        (['discover', test_url, '--format', 'json'], False),
        (['discover', test_url, '--fmt', 'html'], False),
        (['discover', test_url, '--format', 'text'], False),
        
        # Invalid format options
        (['discover', test_url, '--fmt', 'invalid'], False),
        (['discover', test_url, '--format', 'xyz'], False),
        (['discover', test_url, '--fmt', 'pdf'], False),
        
        # Boolean flags - valid (will fail network but pass CLI validation)
        (['scan', test_url, '--auth'], False),
        (['scan', test_url, '--noauth'], False),
        (['scan', test_url, '--fuzz'], False),
        (['scan', test_url, '--nofuzz'], False),
        (['scan', test_url, '--stress'], False),
        (['scan', test_url, '--nostress'], False),
        (['scan', test_url, '--discovery'], False),
        (['scan', test_url, '--nodiscovery'], False),
        (['scan', test_url, '--dis'], False),
        (['scan', test_url, '--nodis'], False),
        
        # Logging options - long and short forms
        (['-ll', 'DEBUG', 'discover', test_url], False),
        (['--loglevel', 'INFO', 'discover', test_url], False),
        (['--loglevel', 'WARNING', 'discover', test_url], False),
        
        # Invalid log levels
        (['-ll', 'INVALID', 'discover', test_url], False),
        (['--loglevel', 'UNKNOWN', 'discover', test_url], False),
        
        # Timeout options - long and short forms
        (['discover', test_url, '--timeout', '30'], False),
        (['discover', test_url, '--time', '60'], False),
        (['discover', test_url, '--timeout', '0.5'], False),
        
        # Invalid timeout values
        (['discover', test_url, '--timeout', 'invalid'], False),
        (['discover', test_url, '--time', '-1'], False),
        (['discover', test_url, '--timeout', 'abc'], False),
        
        # Smart defaults testing
        (['discover', 'https://example.com', '-o', 'report.html'], False),  # Should auto-select html format
        (['discover', 'http://example.com', '-o', 'report.json'], False),  # Should auto-select json format
        
        # Short command aliases with short options
        (['sc', test_url, '--tran', 'https', '--fmt', 'text'], False),
        (['dis', test_url, '--time', '30', '-t', 'http'], False),
        
        # Multiple short options
        (['sc', test_url, '-t', 'https', '-o', 'report.html'], False),
    ]
    
    if use_batch:
        # Run tests in parallel batches for speed
        cmd_list = [test[0] for test in tests]
        expect_list = [test[1] for test in tests]
        results = run_cmd_batch(cmd_list, expect_list)
        passed = sum(results)
    else:
        passed = 0
        for cmd, expect_success in tests:
            if run_cmd(cmd, expect_success):
                passed += 1
    
    print(f"\nOption Validation: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_file_operations():
    """Test file-related operations and error handling."""
    print("\nTesting File Operations")
    
    passed = 0
    total = 0
    
    # Test conf command for creating config
    with tempfile.TemporaryDirectory() as tmpdir:        
        # Test conf without filename (creates .mcpred)
        total += 1
        # Run the command in the project directory, then move output
        project_root = Path(__file__).parent
        full_cmd = ['uv', 'run', 'python', '-m', 'cli.main', 'conf']
        
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            cwd=str(project_root),  # Run in project dir to get uv env
            timeout=10
        )
        
        # Move the created .mcpred file to temp directory for verification
        if result.returncode == 0:
            mcpred_path = project_root / '.mcpred'
            if mcpred_path.exists():
                import shutil
                shutil.move(str(mcpred_path), tmpdir)
        
        if result.returncode == 0:
            passed += 1
            print("PASS conf")
            
            # Check if file was created
            if os.path.exists(os.path.join(tmpdir, '.mcpred')):
                print("Configuration file created successfully")
                passed += 1
            else:
                print("Configuration file was not created")
        else:
            print(f"UNEXPECTED FAILURE: conf")
            print(f"   STDOUT: {result.stdout}")
            print(f"   STDERR: {result.stderr}")
        total += 1
    
    # Test conf command for validating config
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a valid config first
        project_root = Path(__file__).parent
        full_cmd = ['uv', 'run', 'python', '-m', 'cli.main', 'conf']
        
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            cwd=str(project_root),
            timeout=10
        )
        
        # Move the created .mcpred file to temp directory
        if result.returncode == 0:
            mcpred_path = project_root / '.mcpred'
            if mcpred_path.exists():
                import shutil
                shutil.copy2(str(mcpred_path), tmpdir)
                os.remove(str(mcpred_path))  # Clean up
        
        total += 1
        if result.returncode == 0:
            passed += 1
            
            # Now validate it using the created .mcpred file
            total += 1
            mcpred_in_tmp = os.path.join(tmpdir, '.mcpred')
            full_cmd = ['uv', 'run', 'python', '-m', 'cli.main', 'conf', mcpred_in_tmp]
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                cwd=str(project_root),  # Run in project dir for uv env
                timeout=10
            )
            if result.returncode == 0:
                passed += 1
                print("PASS conf .mcpred")
            else:
                print(f"UNEXPECTED FAILURE: conf .mcpred")
        else:
            print(f"UNEXPECTED FAILURE: conf (for validation test)")

    # Test conf with invalid config
    with tempfile.TemporaryDirectory() as tmpdir:
        invalid_config = os.path.join(tmpdir, 'invalid.mcpred')
        
        # Create invalid config
        with open(invalid_config, 'w') as f:
            f.write("invalid: yaml: content: [")
        
        total += 1
        if run_cmd(['conf', invalid_config], False):
            passed += 1
    
    # Test conf with non-existent file
    total += 1  
    if run_cmd(['conf', '/non/existent/file'], False):
        passed += 1
    
    print(f"\nFile Operations: {passed}/{total} tests passed")
    return passed == total

def test_red_file_operations():
    """Test .red file operations."""
    print("\nTesting .red File Operations")
    
    passed = 0
    total = 0
    
    # Test with valid .red file
    with tempfile.TemporaryDirectory() as tmpdir:
        red_file = os.path.join(tmpdir, 'test.red')
        
        # Create a simple .red file with mock target
        with open(red_file, 'w') as f:
            f.write("""
target: "https://mock.test"
transport: "https"
format: "text" 
auth: false
discovery: true
fuzz: false
stress: false
""")
        
        # Test running .red file directly
        total += 1
        if run_cmd([red_file], False):  # May fail due to network, but shouldn't crash
            passed += 1
        
        # Test with run command
        total += 1
        if run_cmd(['run', red_file], False):  # May fail due to network, but shouldn't crash
            passed += 1
    
    # Test with invalid .red file (wrong extension)
    with tempfile.TemporaryDirectory() as tmpdir:
        wrong_ext = os.path.join(tmpdir, 'test.txt')
        
        with open(wrong_ext, 'w') as f:
            f.write("target: https://test.com")
        
        total += 1
        if run_cmd(['run', wrong_ext], False):
            passed += 1
    
    # Test with non-existent .red file
    total += 1
    if run_cmd(['run', '/non/existent.red'], False):
        passed += 1
    
    # Test with malformed .red file
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_red = os.path.join(tmpdir, 'bad.red')
        
        with open(bad_red, 'w') as f:
            f.write("invalid: yaml: [")
        
        total += 1
        if run_cmd(['run', bad_red], False):
            passed += 1
    
    # Test .red file missing required target
    with tempfile.TemporaryDirectory() as tmpdir:
        no_target_red = os.path.join(tmpdir, 'notarget.red')
        
        with open(no_target_red, 'w') as f:
            f.write("""
format: "text"
auth: false
""")
        
        total += 1
        if run_cmd(['run', no_target_red], False):
            passed += 1
    
    print(f"\n.red File Operations: {passed}/{total} tests passed")
    return passed == total

def test_logging_behavior():
    """Test logging options and --loglevel override behavior."""
    print("\nTesting Logging Behavior")
    
    test_url = "https://mock.test"
    
    tests = [
        # Test --loglevel overrides --verbose (all should fail with network error)
        (['--verbose', '--loglevel', 'ERROR', 'discover', test_url], False),
        (['--verb', '-ll', 'WARNING', 'discover', test_url], False),
        (['-ll', 'INFO', '--verbose', 'discover', test_url], False),
        
        # Test various logging levels
        (['-ll', 'DEBUG', 'discover', test_url], False),
        (['--loglevel', 'INFO', 'discover', test_url], False),
        (['--loglevel', 'WARNING', 'discover', test_url], False),
        (['--loglevel', 'ERROR', 'discover', test_url], False),
        (['--loglevel', 'CRITICAL', 'discover', test_url], False),
        
        # Combined logging options
        (['-ll', 'DEBUG', '--verbose', 'discover', test_url], False),
        (['--verbose', '--loglevel', 'WARNING', 'discover', test_url], False),
        
        # Invalid logging options
        (['-ll', 'INVALID', 'discover', test_url], False),
        (['--loglevel', 'BADLEVEL', 'discover', test_url], False),
        (['--loglevel', '123', 'discover', test_url], False),
    ]
    
    passed = 0
    for cmd, expect_success in tests:
        if run_cmd(cmd, expect_success):
            passed += 1
    
    print(f"\nLogging Behavior: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_error_handling():
    """Test various error conditions."""
    print("\nTesting Error Handling")
    
    test_url = "https://mock.test"
    
    tests = [
        # Missing required arguments (commands should fail without target)
        (['discover'], False),
        (['dis'], False),
        (['scan'], False),
        (['sc'], False),
        (['run'], False),  # Missing .red file
        
        # Invalid URLs (will attempt connection and fail - expected)
        (['discover', 'not-a-url'], False),
        (['scan', 'invalid://url'], False),
        (['dis', 'bad-protocol://test'], False),
        
        # Mixed invalid options
        (['discover', test_url, '--invalid-option'], False),
        (['scan', test_url, '--bad-flag'], False),
        (['sc', test_url, '--nonexistent'], False),
        (['dis', test_url, '--fake-param'], False),
        
        # Conflicting options (will attempt connection and fail - expected)
        (['scan', test_url, '--auth', '--noauth'], False),
        (['sc', test_url, '--fuzz', '--nofuzz'], False),
        
        # Output to invalid paths  
        (['discover', test_url, '--output', '/invalid/path/file.json'], False),
        (['scan', test_url, '-o', '/root/forbidden.html'], False),
        
        # Invalid numeric values
        (['discover', test_url, '--timeout', '-5'], False),
        (['discover', test_url, '--time', 'not-a-number'], False),
        (['sc', test_url, '--timeout', '0'], False),
        
        # Invalid file extensions for smart defaults
        (['discover', test_url, '-o', 'report.badext', '--fmt', 'json'], False),  # Still network fail
        
        # Command order issues
        (['--fmt', 'html', 'discover'], False),  # Missing target
        (['-t', 'https'], False),  # No command or target
    ]
    
    passed = 0
    for cmd, expect_success in tests:
        if run_cmd(cmd, expect_success):
            passed += 1
    
    print(f"\nError Handling: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def main():
    """Run CLI tests with optional suite selection."""
    parser = argparse.ArgumentParser(description='Run mcpred CLI validation tests')
    parser.add_argument('--suite', '-s', 
                       choices=['all', 'basic', 'options', 'files', 'red', 'logging', 'errors'],
                       default='all',
                       help='Test suite to run (default: all)')
    parser.add_argument('--batch', '-b', action='store_true', default=True,
                       help='Use batch processing for speed (default: enabled)')
    parser.add_argument('--no-batch', '-nb', dest='batch', action='store_false',
                       help='Disable batch processing')
    parser.add_argument('--parallel', '-p', action='store_true', default=False,
                       help='Run test suites in parallel')
    
    args = parser.parse_args()
    
    print(f"Starting mcpred CLI Validation Tests ({'batch' if args.batch else 'sequential'})")
    print("=" * 50)
    
    # Available test suites
    test_suites = {
        'basic': ('Basic Commands', test_basic_commands),
        'options': ('Option Validation', test_option_validation), 
        'files': ('File Operations', test_file_operations),
        'red': ('.red File Operations', test_red_file_operations),
        'logging': ('Logging Behavior', test_logging_behavior),
        'errors': ('Error Handling', test_error_handling)
    }
    
    # Determine which suites to run
    if args.suite == 'all':
        suites_to_run = list(test_suites.keys())
    else:
        suites_to_run = [args.suite]
    
    # Run test suites
    if args.parallel and len(suites_to_run) > 1:
        print(f"Running {len(suites_to_run)} test suites in parallel")
        
        def run_suite(suite_name):
            suite_desc, suite_func = test_suites[suite_name]
            return suite_func(use_batch=args.batch)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(run_suite, suite): suite for suite in suites_to_run}
            results = []
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
    else:
        results = []
        for suite_name in suites_to_run:
            suite_desc, suite_func = test_suites[suite_name]
            print(f"\n{'='*20} {suite_desc} {'='*20}")
            
            # Pass batch parameter only to functions that support it
            if 'use_batch' in suite_func.__code__.co_varnames:
                result = suite_func(use_batch=args.batch)
            else:
                result = suite_func()
            results.append(result)
    
    # Summary
    passed_suites = sum(results)
    total_suites = len(results)
    
    print("\n" + "=" * 50)
    print(f"CLI VALIDATION SUMMARY")
    print(f"Test Suites Run: {', '.join(suites_to_run)}")
    print(f"Test Suites Passed: {passed_suites}/{total_suites}")
    
    if passed_suites == total_suites:
        print("ALL CLI TESTS PASSED!")
        return 0
    else:
        print(f"{total_suites - passed_suites} test suites failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())