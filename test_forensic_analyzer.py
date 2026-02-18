"""Tests for the forensic application analysis feature."""
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
import os
import sys

# Mock PyQt6 modules so tests can run without a display server
for mod_name in [
    'PyQt6', 'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui',
    'PyQt6.QtChart',
]:
    sys.modules[mod_name] = MagicMock()

# Provide concrete stubs for classes used at module level
_mock_core = sys.modules['PyQt6.QtCore']
_mock_core.QThread = type('QThread', (), {
    '__init__': lambda self, *a, **kw: None,
    'start': lambda self: None,
})
_mock_core.pyqtSignal = lambda *a, **kw: MagicMock()

from localhost_security_analyzer import ForensicAnalyzer


class TestForensicAnalyzerInit(unittest.TestCase):
    """Tests for ForensicAnalyzer initialization."""

    def test_results_contain_app_forensics_key(self):
        analyzer = ForensicAnalyzer()
        self.assertIn('app_forensics', analyzer.results)
        self.assertEqual(analyzer.results['app_forensics'], [])


class TestAnalyzeApplicationsForensic(unittest.TestCase):
    """Tests for the _analyze_applications_forensic method."""

    def setUp(self):
        self.analyzer = ForensicAnalyzer()

    @patch('psutil.process_iter')
    def test_analyze_applications_forensic_basic(self, mock_process_iter):
        """Test basic forensic analysis produces results."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 1234,
            'name': 'test_app.exe',
            'exe': '/usr/bin/test_app',
            'cmdline': ['test_app', '--flag'],
            'cwd': '/home/user',
            'username': 'testuser',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 1.5,
            'memory_info': MagicMock(rss=1024*1024*50, vms=1024*1024*100),
            'num_threads': 4
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        self.assertEqual(len(self.analyzer.results['app_forensics']), 1)
        app = self.analyzer.results['app_forensics'][0]
        self.assertEqual(app['pid'], 1234)
        self.assertEqual(app['name'], 'test_app.exe')
        self.assertEqual(app['exe_path'], '/usr/bin/test_app')
        self.assertEqual(app['username'], 'testuser')

    @patch('psutil.process_iter')
    def test_risk_assessment_low(self, mock_process_iter):
        """Test that a normal process gets LOW risk."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 100,
            'name': 'normal_process',
            'exe': '/usr/bin/normal',
            'cmdline': ['normal'],
            'cwd': '/home',
            'username': 'user',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 0,
            'memory_info': MagicMock(rss=1024*1024, vms=1024*1024*2),
            'num_threads': 2
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        app = self.analyzer.results['app_forensics'][0]
        self.assertEqual(app['risk_assessment']['level'], 'LOW')
        self.assertEqual(app['risk_assessment']['score'], 0)

    @patch('psutil.process_iter')
    def test_risk_assessment_malware_name(self, mock_process_iter):
        """Test that a process with a known malware name gets high risk."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 200,
            'name': 'mimikatz',
            'exe': '/tmp/mimikatz',
            'cmdline': ['mimikatz'],
            'cwd': '/tmp',
            'username': 'attacker',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 10,
            'memory_info': MagicMock(rss=1024*1024*10, vms=1024*1024*20),
            'num_threads': 3
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        app = self.analyzer.results['app_forensics'][0]
        self.assertIn(app['risk_assessment']['level'], ('CRITICAL', 'HIGH'))
        self.assertGreaterEqual(app['risk_assessment']['score'], 40)

    @patch('psutil.process_iter')
    def test_risk_assessment_temp_directory(self, mock_process_iter):
        """Test that a process running from temp gets higher risk."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 300,
            'name': 'suspicious.exe',
            'exe': '/tmp/suspicious.exe',
            'cmdline': ['suspicious.exe'],
            'cwd': '/tmp',
            'username': 'user',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 0,
            'memory_info': MagicMock(rss=1024*1024, vms=1024*1024*2),
            'num_threads': 1
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        app = self.analyzer.results['app_forensics'][0]
        self.assertGreaterEqual(app['risk_assessment']['score'], 30)
        self.assertTrue(any('temporal' in r for r in app['risk_assessment']['reasons']))

    @patch('psutil.process_iter')
    def test_memory_info_calculated(self, mock_process_iter):
        """Test that memory info is correctly calculated."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 400,
            'name': 'memtest',
            'exe': '/usr/bin/memtest',
            'cmdline': ['memtest'],
            'cwd': '/',
            'username': 'user',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 0,
            'memory_info': MagicMock(rss=52428800, vms=104857600),  # 50MB / 100MB
            'num_threads': 1
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        app = self.analyzer.results['app_forensics'][0]
        self.assertEqual(app['memory']['rss_mb'], 50.0)
        self.assertEqual(app['memory']['vms_mb'], 100.0)

    @patch('psutil.process_iter')
    def test_deduplication_by_exe(self, mock_process_iter):
        """Test that the same exe is only analyzed once."""
        def make_proc(pid, name, exe):
            proc = MagicMock()
            proc.info = {
                'pid': pid,
                'name': name,
                'exe': exe,
                'cmdline': [name],
                'cwd': '/',
                'username': 'user',
                'status': 'running',
                'create_time': datetime.now().timestamp(),
                'cpu_percent': 0,
                'memory_info': MagicMock(rss=1024, vms=2048),
                'num_threads': 1
            }
            proc.memory_maps.return_value = []
            proc.open_files.return_value = []
            proc.net_connections.return_value = []
            proc.children.return_value = []
            return proc

        mock_process_iter.return_value = [
            make_proc(1, 'app', '/usr/bin/app'),
            make_proc(2, 'app', '/usr/bin/app'),
            make_proc(3, 'other', '/usr/bin/other'),
        ]

        self.analyzer._analyze_applications_forensic()

        self.assertEqual(len(self.analyzer.results['app_forensics']), 2)

    @patch('psutil.process_iter')
    def test_access_denied_handled(self, mock_process_iter):
        """Test that AccessDenied exceptions are handled gracefully."""
        import psutil as _psutil
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 1,
            'name': 'system',
            'exe': None,
            'cmdline': None,
            'cwd': None,
            'username': None,
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 0,
            'memory_info': None,
            'num_threads': 0
        }
        mock_proc.memory_maps.side_effect = _psutil.AccessDenied(1)
        mock_proc.open_files.side_effect = _psutil.AccessDenied(1)
        mock_proc.net_connections.side_effect = _psutil.AccessDenied(1)
        mock_proc.children.side_effect = _psutil.AccessDenied(1)

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        self.assertEqual(len(self.analyzer.results['app_forensics']), 1)
        app = self.analyzer.results['app_forensics'][0]
        self.assertEqual(app['loaded_modules'], [])
        self.assertEqual(app['open_files'], [])
        self.assertEqual(app['network_connections'], [])
        self.assertEqual(app['children'], [])

    @patch('psutil.process_iter')
    def test_high_thread_count_risk(self, mock_process_iter):
        """Test that high thread count increases risk."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 500,
            'name': 'threaded_app',
            'exe': '/usr/bin/threaded',
            'cmdline': ['threaded'],
            'cwd': '/',
            'username': 'user',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 0,
            'memory_info': MagicMock(rss=1024, vms=2048),
            'num_threads': 150
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        app = self.analyzer.results['app_forensics'][0]
        self.assertGreaterEqual(app['risk_assessment']['score'], 10)
        self.assertTrue(any('hilos' in r for r in app['risk_assessment']['reasons']))

    @patch('psutil.process_iter')
    def test_file_info_os_error_handled(self, mock_process_iter):
        """Test that OSError during file info collection is handled gracefully."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 600,
            'name': 'file_test',
            'exe': '/nonexistent/path/file_test',
            'cmdline': ['file_test'],
            'cwd': '/',
            'username': 'user',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 0,
            'memory_info': MagicMock(rss=1024, vms=2048),
            'num_threads': 1
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        app = self.analyzer.results['app_forensics'][0]
        # file_info should be empty dict when exe doesn't exist
        self.assertEqual(app['file_info'], {})

    @patch('psutil.process_iter')
    def test_linux_temp_directory_risk(self, mock_process_iter):
        """Test that a process in /tmp gets higher risk (cross-platform)."""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 700,
            'name': 'suspicious_linux',
            'exe': '/tmp/suspicious_linux',
            'cmdline': ['suspicious_linux'],
            'cwd': '/tmp',
            'username': 'user',
            'status': 'running',
            'create_time': datetime.now().timestamp(),
            'cpu_percent': 0,
            'memory_info': MagicMock(rss=1024, vms=2048),
            'num_threads': 1
        }
        mock_proc.memory_maps.return_value = []
        mock_proc.open_files.return_value = []
        mock_proc.net_connections.return_value = []
        mock_proc.children.return_value = []

        mock_process_iter.return_value = [mock_proc]

        self.analyzer._analyze_applications_forensic()

        app = self.analyzer.results['app_forensics'][0]
        self.assertGreaterEqual(app['risk_assessment']['score'], 30)
        self.assertTrue(any('temporal' in r for r in app['risk_assessment']['reasons']))


class TestImportsAndSetup(unittest.TestCase):
    """Tests to verify module setup and imports."""

    def test_logger_is_configured(self):
        """Test that the module has a logger configured."""
        import localhost_security_analyzer
        self.assertTrue(hasattr(localhost_security_analyzer, 'logger'))


if __name__ == '__main__':
    unittest.main()
