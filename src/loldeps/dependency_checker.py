import shutil
import logging
import sys
import subprocess
import json
from itertools import chain
import argparse


logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger(__name__)


class DotNetVulnerabilities:
    def __init__(self, dotnet_vulns_dict):
        self.dotnet_vulns_dicts = dotnet_vulns_dict
        self.critical_vulns = []
        self.high_vulns = []
        self.moderate_vulns = []

    def get_top_level_packages(self) -> dict:
        return self.dotnet_vulns_dicts["projects"][0]["frameworks"][0][
            "topLevelPackages"
        ]

    def get_transitive_level_packages(self) -> dict:
        return self.dotnet_vulns_dicts["projects"][0]["frameworks"][0][
            "transitivePackages"
        ]

    def add_vuln(self, vuln: dict):
        match vuln["severity"]:
            case "Critical":
                self.critical_vulns.append(vuln)
            case "High":
                self.high_vulns.append(vuln)
            case "Moderate":
                self.moderate_vulns.append(vuln)

    def print_vulns(self, ado: bool):
        all_vulns = list(
            chain(self.critical_vulns, self.high_vulns, self.moderate_vulns)
        )

        for vuln in all_vulns:
            if ado:
                print(
                    f"##[Error]Package {vuln['package_name']} has a {vuln['severity']} risk issue. Advisory: {vuln['advisory_url']} ({vuln['package_type']})"
                )
            else:
                print(
                    f"Package name: {vuln['package_name']}\nPackage type: {vuln['package_type']}\nSeverity: {vuln['severity']}\nAdvisory: {vuln['advisory_url']}\n\n"
                )

    def failure_check(self, failure_level: str):
        if failure_level == "critical":
            if len(self.critical_vulns) > 0:
                logger.error(
                    f"Failure threshold met. {len(self.critical_vulns)} critical vulnerabilities found."
                )
                exit(1)
            else:
                logger.error("Failure threshold not met.")
        elif failure_level == "high":
            if len(list(chain(self.critical_vulns, self.high_vulns))) > 0:
                logger.error(
                    f"Failure threshold met. {len(self.critical_vulns)} critical vulnerabilities found and {len(self.high)} high vulnerabilities found."
                )
                exit(1)
            else:
                logger.error("Failure threshold not met.")
        else:
            if (len(list(chain(self.critical_vulns, self.high_vulns, self.moderate_vulns))) > 0):  # fmt: skip
                logger.error(
                    f"Failure threshold met. {len(list(chain(self.critical_vulns, self.high_vulns, self.moderate_vulns)))} vulnerabilities found."
                )
                exit(1)
            else:
                logger.error("Failure threshold not met.")


def categorise_package_vulnerabilities(
    packages: list, dotnet_vulnerabilities: DotNetVulnerabilities, package_type: str
):
    for package in packages:

        for vulnerability in package["vulnerabilities"]:
            vuln = {"package_name": package["id"], "package_type": package_type}
            severity = vulnerability["severity"]
            advisory_url = vulnerability["advisoryurl"]

            vuln["severity"] = severity
            vuln["advisory_url"] = advisory_url

            dotnet_vulnerabilities.add_vuln(vuln)


def check_dotnet_deps(include_transitive: bool, path: str) -> DotNetVulnerabilities:
    dotnet_cmd = subprocess.run(
        [
            "dotnet",
            "list",
            path,
            "package",
            "--vulnerable",
            "--include-transitive",
            "--format",
            "json",
        ],
        capture_output=True,
        encoding="utf-8",
    )
    dotnet_vulns_dict = json.loads(dotnet_cmd.stdout)
    dotnet_vulnerabilities = DotNetVulnerabilities(dotnet_vulns_dict)

    top_level_packages = dotnet_vulnerabilities.get_top_level_packages()

    categorise_package_vulnerabilities(
        top_level_packages, dotnet_vulnerabilities, package_type="top_level"
    )

    if include_transitive:
        transitive_packages = dotnet_vulnerabilities.get_transitive_level_packages()
        categorise_package_vulnerabilities(
            transitive_packages, dotnet_vulnerabilities, package_type="transitive"
        )

    return dotnet_vulnerabilities


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--path",
        help="Path to the directory where your code and package manifest is held.",
        type=str,
    )
    parser.add_argument(
        "--failure-level",
        help="Provide the risk level that must be failed on. Options: critical, high, moderate",
        type=str,
    )
    parser.add_argument(
        "--ado",
        help="Choose if you are running in Azure DevOps pipeline.",
        action="store_true",
    )

    args = parser.parse_args()

    dotnet_check = shutil.which("dotnet")
    include_transitive = True

    failure_threshold_options = ["critical", "high", "moderate"]

    if dotnet_check:
        path = args.path
        dotnet_vulnerabilities = check_dotnet_deps(include_transitive, path)
        ado = args.ado
        dotnet_vulnerabilities.print_vulns(ado)

        if args.failure_level in failure_threshold_options:
            dotnet_vulnerabilities.failure_check(args.failure_level)
        else:
            logger.error("Valid failure level not provided.")
    else:
        logger.error("Dotnet binary could not be found. Please install the dotnet cli.")


if __name__ == "__main__":
    main()
