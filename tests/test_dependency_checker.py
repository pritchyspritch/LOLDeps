import unittest
import sys
import os
from unittest.mock import patch
from io import StringIO

# Ensure the path to src/LOLDeps is added to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/loldeps')))

from dependency_checker import DotNetVulnerabilities

class TestDotNetVulnerabilities(unittest.TestCase):

    vuln = {
            "package_name": "PackageA",
            "severity": "Critical",
            "advisory_url": "http://example.com/advisory",
            "package_type": "top_level"
        }

    def setUp(self):
        self.dotnet_vulns_dict = {
            "projects": [{
                "frameworks": [{
                    "topLevelPackages": [
                        {"id": "PackageA", "vulnerabilities": []},
                        {"id": "PackageB", "vulnerabilities": []}
                    ],
                    "transitivePackages": [
                        {"id": "PackageC", "vulnerabilities": []}
                    ]
                }]
            }]
        }

    def test_get_top_level_packages(self):
        dotnet_vulns = DotNetVulnerabilities(self.dotnet_vulns_dict)
        top_level_packages = dotnet_vulns.get_top_level_packages()
        expected_packages = [
            {"id": "PackageA", "vulnerabilities": []},
            {"id": "PackageB", "vulnerabilities": []}
        ]
        self.assertEqual(top_level_packages, expected_packages)

    def test_get_transitive_level_packages(self):
        dotnet_vulns = DotNetVulnerabilities(self.dotnet_vulns_dict)
        transitive_level_packages = dotnet_vulns.get_transitive_level_packages()
        expected_packages = [
            {"id": "PackageC", "vulnerabilities": []}
        ]
        self.assertEqual(transitive_level_packages, expected_packages)

    def test_add_vuln(self):
        dotnet_vulns = DotNetVulnerabilities(self.dotnet_vulns_dict)
        dotnet_vulns.add_vuln(self.vuln)
        self.assertIn(self.vuln, dotnet_vulns.critical_vulns)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_vulns(self, mock_stdout):
        dotnet_vulns = DotNetVulnerabilities(self.dotnet_vulns_dict)
        dotnet_vulns.add_vuln(self.vuln)
        dotnet_vulns.print_vulns(ado=False)
        expected_output = (
            "Package name: PackageA\n"
            "Package type: top_level\n"
            "Severity: Critical\n"
            "Advisory: http://example.com/advisory\n\n\n"
        )
        self.assertEqual(mock_stdout.getvalue(), expected_output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_vulns_ado(self, mock_stdout):
        dotnet_vulns = DotNetVulnerabilities(self.dotnet_vulns_dict)
        dotnet_vulns.add_vuln(self.vuln)
        dotnet_vulns.print_vulns(ado=True)  # Just to ensure no exceptions are raised
        expected_output_ado = (
            "##[Error]Package PackageA has a Critical risk issue. Advisory: http://example.com/advisory (top_level)\n"
        )
        self.assertEqual(mock_stdout.getvalue(), expected_output_ado)

    def test_failure_check(self):
        dotnet_vulns = DotNetVulnerabilities(self.dotnet_vulns_dict)
        dotnet_vulns.add_vuln(self.vuln)
        with self.assertRaises(SystemExit) as critical_exit:
            dotnet_vulns.failure_check("critical")
        self.assertEqual(critical_exit.exception.code, 1)

if __name__ == '__main__':
    unittest.main()