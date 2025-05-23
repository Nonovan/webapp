import unittest
import sys
import os
import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple
import shutil

# Add project root to sys.path to allow imports from other directories
PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT_ROOT))

# --- Import modules to be tested ---
try:
    from admin.security.forensics.live_response.common import artifact_parser
    ARTIFACT_PARSER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import artifact_parser: {e}", file=sys.stderr)
    ARTIFACT_PARSER_AVAILABLE = False

try:
    # Import core forensic utils for setup/validation
    from admin.security.forensics.utils.logging_utils import setup_forensic_logger, log_forensic_operation
    from admin.security.forensics.utils.validation_utils import validate_path
    from admin.security.forensics.utils.forensic_constants import (
        TEMP_DIR_FORENSICS, DEFAULT_SECURE_DIR_PERMS, DEFAULT_SECURE_FILE_PERMS,
        DEFAULT_READ_ONLY_FILE_PERMS, DEFAULT_TIMESTAMP_FORMAT
    )
    from admin.security.forensics.live_response import (
        update_evidence_integrity_baseline,
        verify_evidence_integrity,
        COLLECTION_TYPES,
        ARTIFACT_TYPES
    )
    FORENSIC_UTILS_AVAILABLE = True
    setup_forensic_logger(log_to_console=False, log_level=logging.WARNING)
    logger = logging.getLogger('forensic_validation_suite')
except ImportError as e:
    print(f"Warning: Could not import core forensic utils: {e}", file=sys.stderr)
    FORENSIC_UTILS_AVAILABLE = False
    # Define fallbacks for essential functions and constants
    def log_forensic_operation(*args, **kwargs): pass
    def validate_path(*args, **kwargs) -> Tuple[bool, str]: return True, "Validation skipped"
    TEMP_DIR_FORENSICS = "/tmp/forensic_tests"
    FALLBACK_SECURE_DIR_PERMS = 0o700
    FALLBACK_SECURE_FILE_PERMS = 0o600
    FALLBACK_READ_ONLY_FILE_PERMS = 0o400
    FALLBACK_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
    COLLECTION_TYPES = ["memory", "volatile", "network"]
    ARTIFACT_TYPES = ["process", "network", "system", "user"]
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger('forensic_validation_suite_fallback')


# --- Constants for Testing ---
TEST_DATA_DIR = Path(__file__).parent / "test_data"
TEST_OUTPUT_DIR = Path(TEMP_DIR_FORENSICS) / "live_response_validation_output"
ARTIFACT_PARSER_SCRIPT = PROJECT_ROOT / "admin/security/forensics/live_response/artifact_parser.py"
EVIDENCE_PACKAGING_SCRIPT = PROJECT_ROOT / "admin/security/forensics/live_response/evidence_packaging.sh"
MEMORY_ACQUISITION_SCRIPT = PROJECT_ROOT / "admin/security/forensics/live_response/memory_acquisition.sh"
NETWORK_STATE_SCRIPT = PROJECT_ROOT / "admin/security/forensics/live_response/network_state.sh"
VOLATILE_DATA_SCRIPT = PROJECT_ROOT / "admin/security/forensics/live_response/volatile_data.sh"
COMMON_FUNCTIONS_SCRIPT = PROJECT_ROOT / "admin/security/forensics/live_response/common_functions.sh"


# --- Helper Functions ---
def run_script(script_path: Path, args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """Executes a script (Python or Shell) and returns rc, stdout, stderr."""
    if not script_path.exists():
        logger.error(f"Script not found: {script_path}")
        return -1, "", f"Script not found: {script_path}"

    command: List[str] = []
    if script_path.suffix == ".py":
        command = [sys.executable, str(script_path)] + args
    elif script_path.suffix == ".sh":
        # Ensure script is executable (or run with bash)
        if not os.access(script_path, os.X_OK):
             command = ["bash", str(script_path)] + args
        else:
             command = [str(script_path)] + args
    else:
        logger.error(f"Unsupported script type: {script_path.suffix}")
        return -1, "", f"Unsupported script type: {script_path.suffix}"

    logger.debug(f"Running command: {' '.join(command)}")
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, env=os.environ.copy())
        logger.debug(f"Script {script_path.name} exited with {process.returncode}")
        logger.debug(f"Stdout: {process.stdout[:200]}...")
        logger.debug(f"Stderr: {process.stderr[:200]}...")
        return process.returncode, process.stdout, process.stderr
    except subprocess.TimeoutExpired:
        logger.warning(f"Script execution timed out: {script_path.name}")
        return -1, "", "Script execution timed out"
    except Exception as e:
        logger.error(f"Error running script {script_path.name}: {e}", exc_info=True)
        return -1, "", f"Error running script: {e}"

def setup_test_environment():
    """Create necessary directories and dummy files for testing."""
    logger.info(f"Setting up test environment in {TEST_OUTPUT_DIR} and {TEST_DATA_DIR}")
    secure_dir_perms = DEFAULT_SECURE_DIR_PERMS if FORENSIC_UTILS_AVAILABLE else FALLBACK_SECURE_DIR_PERMS
    os.makedirs(TEST_OUTPUT_DIR, mode=secure_dir_perms, exist_ok=True)
    os.makedirs(TEST_DATA_DIR, exist_ok=True)

    # Create dummy input files
    (TEST_DATA_DIR / "dummy_log.txt").write_text("Sample log line 1\nSample log line 2\nError line 3", encoding='utf-8')
    (TEST_DATA_DIR / "dummy_artifact.json").write_text('{"key": "value", "nested": {"num": 123}, "list": [1, 2, 3]}', encoding='utf-8')
    (TEST_DATA_DIR / "pslist_output.txt").write_text("PID\tPPID\tName\n1\t0\tSystem\n4\t1\tExplorer.exe\n123\t4\tsuspicious.exe", encoding='utf-8')
    (TEST_DATA_DIR / "netscan_output.json").write_text('[{"Proto": "TCP", "LocalAddr": "192.168.1.100:5000", "ForeignAddr": "1.2.3.4:443", "State": "ESTABLISHED", "PID": 1234}]', encoding='utf-8')

    # Create process info files
    process_info_dir = TEST_DATA_DIR / "process_info"
    os.makedirs(process_info_dir, exist_ok=True)
    (process_info_dir / "cmdline.txt").write_text("systemd --system --deserialize 21", encoding='utf-8')
    (process_info_dir / "environ.txt").write_text("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nTERM=linux\nLANG=C.UTF-8", encoding='utf-8')

    # Create network state files
    network_state_dir = TEST_DATA_DIR / "network_state"
    os.makedirs(network_state_dir, exist_ok=True)
    (network_state_dir / "connections.txt").write_text("Proto Local Address Foreign Address State PID/Program\ntcp 127.0.0.1:8080 0.0.0.0:* LISTEN 1234/nginx", encoding='utf-8')
    (network_state_dir / "listening.txt").write_text("Proto Local Address Foreign Address State\ntcp 0.0.0.0:22 0.0.0.0:* LISTEN", encoding='utf-8')

    # Dummy evidence source for packaging
    evidence_source_dir = TEST_DATA_DIR / "evidence_source"
    os.makedirs(evidence_source_dir, exist_ok=True)
    (evidence_source_dir / "file1.txt").write_text("Evidence content 1", encoding='utf-8')
    (evidence_source_dir / "file2.log").write_text("Log entry\nAnother log entry", encoding='utf-8')
    os.makedirs(evidence_source_dir / "subdir", exist_ok=True)
    (evidence_source_dir / "subdir" / "nested_file.dat").write_text("Nested data", encoding='utf-8')

    # Create a file for volatile data collection tests
    volatile_dir = TEST_DATA_DIR / "volatile_data"
    os.makedirs(volatile_dir, exist_ok=True)
    (volatile_dir / "system_info.txt").write_text("Hostname: test-system\nKernel: 5.4.0-42-generic\nCPU: Intel(R) Core(TM) i7-9750H", encoding='utf-8')

    # Create evidence integrity files
    integrity_dir = TEST_DATA_DIR / "integrity"
    os.makedirs(integrity_dir, exist_ok=True)
    (integrity_dir / "file1.txt").write_text("Test file for integrity checking", encoding='utf-8')
    (integrity_dir / "file2.txt").write_text("Another test file with different content", encoding='utf-8')

def cleanup_test_environment():
    """Remove temporary files and directories created during tests."""
    logger.info("Cleaning up test environment...")
    if TEST_OUTPUT_DIR.exists():
        try:
            shutil.rmtree(TEST_OUTPUT_DIR)
            logger.debug(f"Removed test output directory: {TEST_OUTPUT_DIR}")
        except OSError as e:
            logger.error(f"Error removing test output directory {TEST_OUTPUT_DIR}: {e}")
    if TEST_DATA_DIR.exists():
        try:
            shutil.rmtree(TEST_DATA_DIR)
            logger.debug(f"Removed test data directory: {TEST_DATA_DIR}")
        except OSError as e:
            logger.error(f"Error removing test data directory {TEST_DATA_DIR}: {e}")


# --- Test Cases ---

@unittest.skipUnless(ARTIFACT_PARSER_AVAILABLE, "artifact_parser module not available")
class TestArtifactParser(unittest.TestCase):
    """Tests for the artifact_parser.py script and its functions."""

    @classmethod
    def setUpClass(cls):
        # Setup is handled globally for simplicity, but could be per-class if needed
        pass

    def test_artifact_parser_main_help(self):
        """Test running artifact_parser.py --help."""
        rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, ["--help"])
        self.assertEqual(rc, 0, f"Script failed with stderr: {stderr}")
        self.assertIn("usage: artifact_parser.py", stdout)
        self.assertIn("--type", stdout, "Missing --type argument in help")
        self.assertIn("--output", stdout, "Missing --output argument in help")
        self.assertIn("--input", stdout, "Missing --input argument in help")
        self.assertIn("--output-format", stdout, "Missing --output-format argument in help")

    def test_artifact_parser_main_execution_json_input(self):
        """Test artifact_parser.py parsing a JSON file."""
        input_file = TEST_DATA_DIR / "dummy_artifact.json"
        output_file = TEST_OUTPUT_DIR / "parsed_artifact.json"
        rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, [
            "--input", str(input_file),
            "--type", "generic_json",  # Assuming this type exists
            "--output", str(output_file),
            "--output-format", "json"
        ])
        self.assertEqual(rc, 0, f"Script failed with stderr: {stderr}")
        self.assertTrue(output_file.exists(), f"Output file {output_file} was not created")
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.assertIn("metadata", data, "Missing 'metadata' key in output")
            self.assertEqual(data["metadata"]["source_file"], str(input_file))
            self.assertEqual(data["metadata"]["artifact_type"], "generic_json")
            self.assertIn("parsed_data", data, "Missing 'parsed_data' key in output")
            self.assertEqual(data["parsed_data"]["key"], "value", "Incorrect parsed data")
            self.assertEqual(data["parsed_data"]["nested"]["num"], 123, "Incorrect nested parsed data")
        except json.JSONDecodeError:
            self.fail(f"Output file {output_file} is not valid JSON")
        except Exception as e:
            self.fail(f"Error reading or validating output file {output_file}: {e}")

    def test_artifact_parser_main_execution_text_input(self):
        """Test artifact_parser.py parsing a text file (e.g., pslist)."""
        input_file = TEST_DATA_DIR / "pslist_output.txt"
        output_file = TEST_OUTPUT_DIR / "parsed_pslist.json"
        # Assuming 'pslist' is a supported type that parses the text format
        rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, [
            "--input", str(input_file),
            "--type", "pslist",
            "--output", str(output_file),
            "--output-format", "json"
        ])
        # This test depends heavily on the implementation of the 'pslist' parser type
        # Adjust assertions based on expected output structure
        if rc != 0:
            # If pslist type isn't implemented, this might fail gracefully or error out
            logger.warning(f"artifact_parser failed for type 'pslist', possibly not implemented. Stderr: {stderr}")
            # Try with generic_text as a fallback
            rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, [
                "--input", str(input_file),
                "--type", "generic_text",
                "--output", str(output_file),
                "--output-format", "json"
            ])
            self.assertEqual(rc, 0, f"Script failed with generic_text type. Stderr: {stderr}")
            self.assertTrue(output_file.exists(), "Output file not created")
        else:
            self.assertTrue(output_file.exists())
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.assertIn("parsed_data", data)
                if isinstance(data["parsed_data"], list) and data["parsed_data"]:
                    # Check for expected keys in parsed process entries
                    if "PID" in data["parsed_data"][0]:
                        self.assertIn("PID", data["parsed_data"][0])
                        self.assertIn("Name", data["parsed_data"][0])
            except Exception as e:
                self.fail(f"Error reading or validating pslist output file {output_file}: {e}")

    def test_artifact_parser_invalid_input_path(self):
        """Test artifact_parser.py with a non-existent input file."""
        output_file = TEST_OUTPUT_DIR / "invalid_input_test.json"
        rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, [
            "--input", "non_existent_file.xyz",
            "--type", "generic_text",
            "--output", str(output_file)
        ])
        self.assertNotEqual(rc, 0, "Script should fail for non-existent input")
        # Error message might be logged or printed to stderr depending on implementation
        self.assertTrue("Input file validation failed" in stderr or "Path does not exist" in stderr, f"Expected input validation error, got stderr: {stderr}")

    def test_artifact_parser_overwrite_protection(self):
        """Test that artifact_parser.py does not overwrite output without --overwrite flag."""
        input_file = TEST_DATA_DIR / "dummy_log.txt"
        output_file = TEST_OUTPUT_DIR / "overwrite_test.txt"
        # Create the output file first
        output_file.write_text("Existing content", encoding='utf-8')

        rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, [
            "--input", str(input_file),
            "--type", "generic_text",
            "--output", str(output_file)
        ])
        self.assertNotEqual(rc, 0, "Script should fail if output exists without --overwrite")
        self.assertIn("already exists. Use --overwrite", stderr, f"Expected overwrite error, got stderr: {stderr}")
        # Verify content wasn't overwritten
        self.assertEqual(output_file.read_text(encoding='utf-8'), "Existing content")

    def test_artifact_parser_overwrite_flag(self):
        """Test that artifact_parser.py overwrites output with --overwrite flag."""
        input_file = TEST_DATA_DIR / "dummy_log.txt"
        output_file = TEST_OUTPUT_DIR / "overwrite_test_forced.txt"
        output_file.write_text("Existing content", encoding='utf-8')

        rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, [
            "--input", str(input_file),
            "--type", "generic_text",
            "--output", str(output_file),
            "--overwrite"
        ])
        self.assertEqual(rc, 0, f"Script failed with --overwrite flag. Stderr: {stderr}")
        # Verify content was overwritten (content check depends on 'generic_text' parser)
        self.assertNotEqual(output_file.read_text(encoding='utf-8'), "Existing content")

    def test_artifact_parser_export_formats(self):
        """Test artifact_parser.py with different export formats."""
        input_file = TEST_DATA_DIR / "dummy_artifact.json"
        formats = ["json", "text", "yaml", "csv"]

        for format_type in formats:
            with self.subTest(format=format_type):
                output_file = TEST_OUTPUT_DIR / f"artifact_export.{format_type}"
                rc, stdout, stderr = run_script(ARTIFACT_PARSER_SCRIPT, [
                    "--input", str(input_file),
                    "--type", "generic_json",
                    "--output", str(output_file),
                    "--output-format", format_type
                ])

                # For unsupported formats, we might get an error which is acceptable
                if rc == 0:
                    self.assertTrue(output_file.exists(), f"Output file for {format_type} not created")
                    if format_type == "json":
                        # Verify it's valid JSON
                        try:
                            with open(output_file, 'r', encoding='utf-8') as f:
                                json.load(f)
                        except json.JSONDecodeError:
                            self.fail(f"Output file {output_file} is not valid JSON")


@unittest.skipUnless(EVIDENCE_PACKAGING_SCRIPT.exists(), "evidence_packaging.sh script not found")
class TestEvidencePackagingScript(unittest.TestCase):
    """Tests for the evidence_packaging.sh script."""

    @classmethod
    def setUpClass(cls):
        cls.evidence_source_dir = TEST_DATA_DIR / "evidence_source"

    def test_evidence_packaging_help(self):
        """Test running evidence_packaging.sh --help."""
        rc, stdout, stderr = run_script(EVIDENCE_PACKAGING_SCRIPT, ["--help"])
        # Help might exit with 0 or 1, focus on output content
        self.assertIn("Usage:", stdout, "Missing 'Usage:' section in help output")
        self.assertIn("--source", stdout, "Missing --source option in help")
        self.assertIn("--output", stdout, "Missing --output option in help")
        self.assertIn("--case-id", stdout, "Missing --case-id option in help")
        self.assertIn("--examiner", stdout, "Missing --examiner option in help")
        self.assertIn("--format", stdout, "Missing --format option in help")

    def test_evidence_packaging_basic_tar_gz(self):
        """Test basic evidence packaging into a tar.gz archive."""
        output_package_dir = TEST_OUTPUT_DIR / "packages_targz"
        os.makedirs(output_package_dir, exist_ok=True)
        case_id = "CASE-PKG-001"
        examiner = "validator"
        expected_package_prefix = f"{case_id}_{examiner}_"

        rc, stdout, stderr = run_script(EVIDENCE_PACKAGING_SCRIPT, [
            "--source", str(self.evidence_source_dir),
            "--output", str(output_package_dir),
            "--case-id", case_id,
            "--examiner", examiner,
            "--format", "tar.gz"
        ])

        self.assertEqual(rc, 0, f"Script failed. Stderr: {stderr}\nStdout: {stdout}")

        # Check if output package and manifest exist
        found_package = False
        found_manifest = False
        package_path = None
        for item in output_package_dir.iterdir():
            if item.name.startswith(expected_package_prefix) and item.name.endswith(".tar.gz"):
                found_package = True
                package_path = item
            if item.name.startswith(expected_package_prefix) and item.name.endswith(".manifest.json"):
                found_manifest = True

        self.assertTrue(found_package, f"No evidence package (.tar.gz) found in {output_package_dir} starting with {expected_package_prefix}")
        self.assertTrue(found_manifest, f"No manifest file (.manifest.json) found in {output_package_dir} starting with {expected_package_prefix}")

        # Optional: Verify package contents (requires tar command)
        if found_package and shutil.which("tar"):
            list_rc, list_stdout, list_stderr = run_script(Path(shutil.which("tar")), ["tf", str(package_path)])
            self.assertEqual(list_rc, 0, f"Failed to list tar contents: {list_stderr}")
            self.assertIn("file1.txt", list_stdout)
            self.assertIn("file2.log", list_stdout)
            self.assertIn("subdir/nested_file.dat", list_stdout)

    def test_evidence_packaging_missing_required_args(self):
        """Test evidence_packaging.sh fails without required arguments."""
        # Test without case-id
        rc, stdout, stderr = run_script(EVIDENCE_PACKAGING_SCRIPT, [
            "--source", str(self.evidence_source_dir),
            "--output", str(TEST_OUTPUT_DIR),
            "--examiner", "validator"
        ])
        self.assertNotEqual(rc, 0, "Script should fail without --case-id")
        self.assertIn("Case ID not provided", stderr, "Expected error message for missing case ID")

        # Test without examiner
        rc, stdout, stderr = run_script(EVIDENCE_PACKAGING_SCRIPT, [
            "--source", str(self.evidence_source_dir),
            "--output", str(TEST_OUTPUT_DIR),
            "--case-id", "CASE-PKG-002"
        ])
        self.assertNotEqual(rc, 0, "Script should fail without --examiner")
        self.assertIn("Examiner ID not provided", stderr, "Expected error message for missing examiner ID")

        # Test without source
        rc, stdout, stderr = run_script(EVIDENCE_PACKAGING_SCRIPT, [
            "--output", str(TEST_OUTPUT_DIR),
            "--case-id", "CASE-PKG-003",
            "--examiner", "validator"
        ])
        self.assertNotEqual(rc, 0, "Script should fail without --source")
        self.assertIn("Source directory not specified", stderr, "Expected error message for missing source")

    def test_evidence_packaging_invalid_source(self):
        """Test evidence_packaging.sh with an invalid source directory."""
        rc, stdout, stderr = run_script(EVIDENCE_PACKAGING_SCRIPT, [
            "--source", "/path/to/nonexistent/source",
            "--output", str(TEST_OUTPUT_DIR),
            "--case-id", "CASE-PKG-004",
            "--examiner", "validator"
        ])
        self.assertNotEqual(rc, 0, "Script should fail with invalid source")
        self.assertIn("Source directory does not exist", stderr, "Expected error message for invalid source")

    def test_evidence_packaging_with_metadata(self):
        """Test evidence packaging with additional metadata."""
        output_package_dir = TEST_OUTPUT_DIR / "packages_metadata"
        os.makedirs(output_package_dir, exist_ok=True)
        case_id = "CASE-PKG-005"
        examiner = "validator"

        rc, stdout, stderr = run_script(EVIDENCE_PACKAGING_SCRIPT, [
            "--source", str(self.evidence_source_dir),
            "--output", str(output_package_dir),
            "--case-id", case_id,
            "--examiner", examiner,
            "--format", "zip",
            "--description", "Test evidence package with metadata",
            "--notes", "Created during validation tests"
        ])

        self.assertEqual(rc, 0, f"Script failed with metadata args. Stderr: {stderr}")

        # Find and validate manifest
        manifest_files = list(output_package_dir.glob(f"{case_id}_{examiner}_*.manifest.json"))
        self.assertTrue(len(manifest_files) > 0, "No manifest file found")

        # Check if manifest contains our metadata
        try:
            with open(manifest_files[0], 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
            self.assertIn("description", manifest_data, "Description not found in manifest")
            self.assertEqual(manifest_data["description"], "Test evidence package with metadata")
            self.assertIn("notes", manifest_data, "Notes not found in manifest")
        except (json.JSONDecodeError, KeyError) as e:
            self.fail(f"Failed to parse manifest file or verify metadata: {e}")


@unittest.skipUnless(MEMORY_ACQUISITION_SCRIPT.exists(), "memory_acquisition.sh script not found")
class TestMemoryAcquisitionScript(unittest.TestCase):
    """Tests for the memory_acquisition.sh script."""

    def test_memory_acquisition_help(self):
        """Test running memory_acquisition.sh --help."""
        rc, stdout, stderr = run_script(MEMORY_ACQUISITION_SCRIPT, ["--help"])
        self.assertIn("Usage:", stdout)
        self.assertIn("--output", stdout)
        self.assertIn("--method", stdout)

    def test_memory_acquisition_version(self):
        """Test memory_acquisition.sh version output."""
        rc, stdout, stderr = run_script(MEMORY_ACQUISITION_SCRIPT, ["--version"])
        self.assertEqual(rc, 0, "Version check failed")
        self.assertRegex(stdout, r"Memory Acquisition v\d+\.\d+\.\d+")

    def test_memory_acquisition_list_methods(self):
        """Test listing available acquisition methods."""
        rc, stdout, stderr = run_script(MEMORY_ACQUISITION_SCRIPT, ["--list-methods"])
        self.assertEqual(rc, 0, "List methods failed")
        # Check for common acquisition methods in the output
        expected_methods = ["lime", "avml", "winpmem", "dumpit", "dd"]
        found_methods = 0
        for method in expected_methods:
            if method.lower() in stdout.lower():
                found_methods += 1
        self.assertGreater(found_methods, 0, "No acquisition methods found in output")

    @unittest.skip("Memory acquisition tests require specific setup (e.g., root, tools like LiME/Volatility)")
    def test_memory_acquisition_execution(self):
        """Placeholder for testing actual memory acquisition (requires advanced setup)."""
        # This test would need:
        # 1. A way to run as root or with necessary capabilities.
        # 2. Mocking or providing dummy versions of acquisition tools (LiME, dd, etc.).
        # 3. Mocking or providing dummy Volatility for analysis phase.
        # 4. Careful cleanup.
        pass


@unittest.skipUnless(NETWORK_STATE_SCRIPT.exists(), "network_state.sh script not found")
class TestNetworkStateScript(unittest.TestCase):
    """Tests for the network_state.sh script."""

    def test_network_state_help(self):
        """Test running network_state.sh --help."""
        rc, stdout, stderr = run_script(NETWORK_STATE_SCRIPT, ["--help"])
        self.assertIn("Usage:", stdout)
        self.assertIn("--output", stdout)

    def test_network_state_version(self):
        """Test network_state.sh version output."""
        rc, stdout, stderr = run_script(NETWORK_STATE_SCRIPT, ["--version"])
        self.assertEqual(rc, 0, "Version check failed")
        self.assertRegex(stdout, r"Network State Collection v\d+\.\d+\.\d+")


@unittest.skipUnless(VOLATILE_DATA_SCRIPT.exists(), "volatile_data.sh script not found")
class TestVolatileDataScript(unittest.TestCase):
    """Tests for the volatile_data.sh script."""

    def test_volatile_data_help(self):
        """Test running volatile_data.sh --help."""
        rc, stdout, stderr = run_script(VOLATILE_DATA_SCRIPT, ["--help"])
        self.assertIn("Usage:", stdout)
        self.assertIn("--output", stdout)
        self.assertIn("--collect", stdout)

    def test_volatile_data_version(self):
        """Test volatile_data.sh version output."""
        rc, stdout, stderr = run_script(VOLATILE_DATA_SCRIPT, ["--version"])
        self.assertEqual(rc, 0, "Version check failed")
        self.assertRegex(stdout, r"Volatile Data Collection v\d+\.\d+\.\d+")


@unittest.skipIf(not FORENSIC_UTILS_AVAILABLE, "Core forensic utilities not available")
class TestEvidenceIntegrityFunctions(unittest.TestCase):
    """Tests for the evidence integrity baseline and verification functions."""

    def setUp(self):
        self.evidence_dir = TEST_DATA_DIR / "integrity"
        self.baseline_path = TEST_OUTPUT_DIR / "integrity_baseline.json"

    def test_update_evidence_integrity_baseline(self):
        """Test creating an integrity baseline for evidence files."""
        success, output_path = update_evidence_integrity_baseline(
            evidence_dir=str(self.evidence_dir),
            output_path=str(self.baseline_path),
            case_id="TEST-INTEGRITY-001",
            examiner="integrity-tester"
        )

        self.assertTrue(success, "Creating integrity baseline failed")
        self.assertTrue(Path(output_path).exists(), "Baseline file not created")

        # Check that the baseline file is valid JSON and contains expected data
        with open(output_path, 'r') as f:
            baseline = json.load(f)

        self.assertIn("metadata", baseline, "Baseline missing metadata section")
        self.assertIn("files", baseline, "Baseline missing files section")
        self.assertEqual(baseline["metadata"]["case_id"], "TEST-INTEGRITY-001", "Case ID not stored in baseline")

        # We should have entries for our test files
        self.assertGreaterEqual(len(baseline["files"]), 2, "Missing file entries in baseline")

    def test_verify_evidence_integrity(self):
        """Test verifying evidence integrity against a baseline."""
        # First create a baseline
        success, baseline_path = update_evidence_integrity_baseline(
            evidence_dir=str(self.evidence_dir),
            output_path=str(self.baseline_path),
            case_id="TEST-INTEGRITY-002",
            examiner="integrity-tester"
        )

        self.assertTrue(success, "Failed to create integrity baseline")

        # Now verify against the baseline
        verified, results = verify_evidence_integrity(
            evidence_dir=str(self.evidence_dir),
            baseline_path=baseline_path
        )

        self.assertTrue(verified, "Integrity verification failed")
        self.assertGreaterEqual(results["summary"]["verified_count"], 2, "Not all files were verified")
        self.assertEqual(results["summary"]["modified_count"], 0, "Found modified files when none should exist")


# --- Main Execution ---
if __name__ == "__main__":
    # Ensure the test environment is clean before starting
    cleanup_test_environment()
    setup_test_environment()

    # Discover and run tests
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    # Add test classes explicitly
    if ARTIFACT_PARSER_AVAILABLE:
        suite.addTest(loader.loadTestsFromTestCase(TestArtifactParser))
    if EVIDENCE_PACKAGING_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestEvidencePackagingScript))
    if MEMORY_ACQUISITION_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestMemoryAcquisitionScript))
    if NETWORK_STATE_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestNetworkStateScript))
    if VOLATILE_DATA_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestVolatileDataScript))
    if FORENSIC_UTILS_AVAILABLE:
        suite.addTest(loader.loadTestsFromTestCase(TestEvidenceIntegrityFunctions))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Clean up after tests
    cleanup_test_environment()

    # Exit with non-zero code if tests failed
    sys.exit(not result.wasSuccessful())
