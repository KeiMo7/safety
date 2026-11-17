from __future__ import annotations

import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from safety.errors import CycloneDxComponentError, CycloneDxOutputError
from safety.formatter import SafetyFormatter
from safety.formatters.cyclonedx import (
    CYCLONEDX_SCHEMA,
    CYCLONEDX_SPEC_VERSION,
    CycloneDXReport,
    CycloneDxReport,
    build_purl,
)
from safety.models import CVE, Package, SafetyRequirement, Severity, Vulnerability


SCHEMA_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "cyclonedx" / "1.5"


def make_requirement(
    name: str, version: str | None = None, found: str | None = "requirements.txt"
) -> SafetyRequirement:
    base_name = "test-package"
    raw = f"{base_name}=={version}" if version else base_name
    requirement = SafetyRequirement(raw, found=found)
    requirement.name = name
    return requirement


def make_package(
    name: str,
    versions: list[str | None],
    found: str | None = "requirements.txt",
    package_name: str | None = None,
) -> Package:
    requirements = [
        make_requirement(name, version=version, found=found) for version in versions
    ]
    version = versions[0] if len(versions) == 1 else None
    return Package(
        name=package_name or name.lower(),
        version=version,
        requirements=requirements,
        found=found,
    )


def make_vulnerability(
    package: Package,
    requirement: SafetyRequirement,
    cve_id: str,
    vulnerability_id: str,
    transitive: bool = False,
) -> Vulnerability:
    cvssv3 = {
        "base_score": 7.5,
        "base_severity": "HIGH",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    }
    cve = CVE(name=cve_id, cvssv2=None, cvssv3=cvssv3)
    version = next(iter(requirement.specifier)).version

    return Vulnerability(
        vulnerability_id=vulnerability_id,
        package_name=package.name,
        pkg=package,
        ignored=False,
        ignored_reason=None,
        ignored_expires=None,
        vulnerable_spec={"<9.0"},
        all_vulnerable_specs=["<9.0"],
        analyzed_version=version,
        analyzed_requirement=requirement,
        advisory=f"Advisory for {cve_id}",
        is_transitive=transitive,
        published_date="2024-01-02",
        fixed_versions=["9.0"],
        closest_versions_without_known_vulnerabilities=[],
        resources=[f"https://example.com/{cve_id}"],
        CVE=cve,
        severity=Severity(source=cve_id, cvssv2=None, cvssv3=cvssv3),
        affected_versions=[version],
        more_info_url=f"https://example.com/{cve_id}",
    )


class RecordingStream(StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.writes = []

    def write(self, value):
        self.writes.append(value)
        return super().write(value)


class FailingStream:
    def write(self, value):
        raise OSError("simulated write failure")

    def flush(self) -> None:
        pass


class TestCycloneDxFormatter(unittest.TestCase):
    def setUp(self) -> None:
        self.formatter = CycloneDxReport()
        schema_resources = [
            (
                "http://cyclonedx.org/schema/bom-1.5.schema.json",
                "bom-1.5.schema.json",
            ),
            (
                "http://cyclonedx.org/schema/spdx.schema.json",
                "spdx.schema.json",
            ),
            (
                "http://cyclonedx.org/schema/jsf-0.82.schema.json",
                "jsf-0.82.schema.json",
            ),
        ]
        registry = Registry()
        for uri, filename in schema_resources:
            schema_data = json.loads(
                (SCHEMA_DIR / filename).read_text(encoding="utf-8")
            )
            registry = registry.with_resource(
                uri,
                Resource.from_contents(schema_data, default_specification=DRAFT7),
            )

        self.schema = json.loads(
            (SCHEMA_DIR / "bom-1.5.schema.json").read_text(encoding="utf-8")
        )
        self.registry = registry

    def render(self, packages, vulnerabilities=None) -> str:
        return self.formatter.render_vulnerabilities(
            announcements=[],
            vulnerabilities=vulnerabilities or [],
            remediations={},
            full=False,
            packages=packages,
            fixes=[],
        )

    def parse(self, packages, vulnerabilities=None):
        return json.loads(self.render(packages, vulnerabilities))

    def assert_valid_schema(self, payload) -> None:
        validator = Draft7Validator(
            self.schema,
            registry=self.registry,
            format_checker=FormatChecker(),
        )
        errors = sorted(
            validator.iter_errors(payload),
            key=lambda error: list(error.path),
        )
        self.assertEqual([], [error.message for error in errors])

    def test_normal_inventory_preserves_name_case_and_namespace(self):
        namespace_package = make_package(
            "Acme/Widget_Pkg",
            ["1.2.3"],
            found="requirements-dev.txt",
        )
        mixed_case_package = make_package(
            "Foo_Bar",
            ["2.0.0"],
            found="requirements.txt",
        )

        payload = self.parse([namespace_package, mixed_case_package])
        self.assert_valid_schema(payload)
        self.assertEqual(CYCLONEDX_SCHEMA, payload["$schema"])
        self.assertEqual(CYCLONEDX_SPEC_VERSION, payload["specVersion"])

        components = payload["components"]
        self.assertEqual(2, len(components))

        namespace_component = next(
            component
            for component in components
            if component["name"] == "Acme/Widget_Pkg"
        )
        self.assertEqual(
            "pkg:pypi/Acme/Widget_Pkg@1.2.3",
            namespace_component["purl"],
        )
        self.assertEqual("library", namespace_component["type"])
        self.assertEqual(
            [
                "type",
                "bom-ref",
                "name",
                "version",
                "purl",
                "evidence",
                "properties",
            ],
            list(namespace_component),
        )

        mixed_case_component = next(
            component for component in components if component["name"] == "Foo_Bar"
        )
        self.assertEqual("pkg:pypi/Foo_Bar@2.0.0", mixed_case_component["purl"])

        root_dependencies = next(
            dependency
            for dependency in payload["dependencies"]
            if dependency["ref"] == "urn:safety:root"
        )
        self.assertIn(namespace_component["bom-ref"], root_dependencies["dependsOn"])
        self.assertIn(mixed_case_component["bom-ref"], root_dependencies["dependsOn"])

    def test_multiple_versions_and_cves_are_not_merged(self):
        package = make_package(
            "Foo_Pkg",
            ["1.0", "2.0", "1.0"],
            found="requirements-prod.txt",
        )
        requirement_v1 = package.requirements[0]
        requirement_v2 = package.requirements[1]
        vulnerabilities = [
            make_vulnerability(package, requirement_v1, "CVE-2024-0001", "1001"),
            make_vulnerability(package, requirement_v1, "CVE-2024-0002", "1002"),
            make_vulnerability(
                package,
                requirement_v2,
                "CVE-2024-0003",
                "1003",
                transitive=True,
            ),
        ]

        payload = self.parse([package], vulnerabilities)
        self.assert_valid_schema(payload)

        components = [
            component
            for component in payload["components"]
            if component["name"] == "Foo_Pkg"
        ]
        self.assertEqual(2, len(components))
        self.assertEqual(
            {"1.0", "2.0"},
            {component["version"] for component in components},
        )

        vulnerability_ids = {
            vulnerability["id"] for vulnerability in payload["vulnerabilities"]
        }
        self.assertEqual(
            {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
            vulnerability_ids,
        )
        self.assertEqual(3, len(payload["vulnerabilities"]))
        for vulnerability in payload["vulnerabilities"]:
            properties = {
                item["name"]: item["value"] for item in vulnerability["properties"]
            }
            self.assertEqual(
                "requirements-prod.txt",
                properties["safety:declaration-file"],
            )

        dependencies = {
            dependency["ref"]: dependency["dependsOn"]
            for dependency in payload["dependencies"]
        }
        direct_ref = next(
            component["bom-ref"]
            for component in components
            if component["version"] == "1.0"
        )
        transitive_ref = next(
            component["bom-ref"]
            for component in components
            if component["version"] == "2.0"
        )
        self.assertEqual([direct_ref], dependencies["urn:safety:root"])
        self.assertEqual([transitive_ref], dependencies[direct_ref])

    def test_missing_metadata_is_unknown_counted_and_retained(self):
        no_version = make_package("No_Version", [None])
        no_source = make_package("No_Source", ["1.0"], found=None)
        missing_everything = Package(
            name=None,
            version=None,
            requirements=[],
            found=None,
        )

        payload = self.parse([no_version, no_source, missing_everything])
        self.assert_valid_schema(payload)

        components = payload["components"]
        self.assertEqual(3, len(components))
        unknown_component = next(
            component
            for component in components
            if component["purl"] == "pkg:pypi/unknown"
        )
        self.assertEqual("unknown", unknown_component["name"])
        self.assertEqual("unknown", unknown_component["version"])
        self.assertEqual("pkg:pypi/unknown", unknown_component["purl"])

        no_version_component = next(
            component for component in components if component["name"] == "No_Version"
        )
        self.assertEqual("unknown", no_version_component["version"])
        self.assertIn(
            {"name": "safety:missing-metadata", "value": "version"},
            no_version_component["properties"],
        )

        no_source_component = next(
            component for component in components if component["name"] == "No_Source"
        )
        self.assertIn(
            {"name": "safety:missing-metadata", "value": "source"},
            no_source_component["properties"],
        )

        metadata_properties = {
            item["name"]: item["value"] for item in payload["metadata"]["properties"]
        }
        self.assertEqual("3", metadata_properties["safety:degraded-components"])
        self.assertEqual("2", metadata_properties["safety:missing-version-components"])
        self.assertEqual("2", metadata_properties["safety:missing-source-components"])
        self.assertEqual("1", metadata_properties["safety:missing-name-components"])

    def test_non_ascii_names_are_escaped_and_purl_encoded(self):
        package = make_package("München_Pkg", ["1.0"])

        rendered = self.render([package])
        payload = json.loads(rendered)
        self.assert_valid_schema(payload)

        component = payload["components"][0]
        self.assertEqual("München_Pkg", component["name"])
        self.assertEqual("pkg:pypi/M%C3%BCnchen_Pkg@1.0", component["purl"])
        self.assertIn("M\\u00fcnchen_Pkg", rendered)

    def test_output_is_byte_reproducible_and_streamed(self):
        packages = [make_package(f"Package_{index}", ["1.0"]) for index in range(300)]
        first = self.render(packages)
        second = self.render(list(reversed(packages)))
        self.assertEqual(first.encode("utf-8"), second.encode("utf-8"))

        stream = RecordingStream()
        self.formatter.write_vulnerabilities(
            stream,
            announcements=[],
            vulnerabilities=[],
            remediations={},
            full=False,
            packages=packages,
            fixes=[],
        )
        self.assertGreater(len(stream.writes), len(packages))
        self.assertLess(max(len(chunk) for chunk in stream.writes), len(first))

    def test_concurrent_renders_have_no_shared_formatter_state(self):
        packages = [make_package(f"Package_{index}", ["1.0"]) for index in range(50)]
        expected = self.render(packages)

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(
                executor.map(
                    lambda _: self.formatter.render_vulnerabilities(
                        announcements=[],
                        vulnerabilities=[],
                        remediations={},
                        full=False,
                        packages=packages,
                        fixes=[],
                    ),
                    range(8),
                )
            )

        self.assertEqual([expected] * 8, results)

    def test_failure_logs_and_exception_do_not_expose_sensitive_values(self):
        secret_absolute_path = "/home/private-user/.cache/requirements.txt"
        secret_credential = "token=super-secret"
        secret_package = "Private_Package"
        package = make_package(
            secret_package,
            ["9.9.9"],
            found=f"{secret_absolute_path}?{secret_credential}",
        )

        with self.assertLogs("safety.formatters.cyclonedx", level="INFO") as logs:
            with self.assertRaises(CycloneDxOutputError) as raised:
                self.formatter.write_vulnerabilities(
                    FailingStream(),
                    announcements=[],
                    vulnerabilities=[],
                    remediations={},
                    full=False,
                    packages=[package],
                    fixes=[],
                )

        sensitive_output = "\n".join(logs.output) + "\n" + str(raised.exception)
        self.assertNotIn(secret_absolute_path, sensitive_output)
        self.assertNotIn(secret_credential, sensitive_output)
        self.assertNotIn(secret_package, sensitive_output)

    def test_component_validation_failure_identifies_component_only(self):
        package = make_package("Unsafe_Pkg", ["1.0"])

        with patch(
            "safety.formatters.cyclonedx.build_purl",
            return_value="invalid-purl",
        ):
            with self.assertLogs("safety.formatters.cyclonedx", level="ERROR") as logs:
                with self.assertRaises(CycloneDxComponentError) as raised:
                    self.render([package])

        self.assertEqual(0, raised.exception.index)
        self.assertEqual("purl", raised.exception.field)
        self.assertIn("component[0]", str(raised.exception))
        self.assertIn("component[0]: purl", "\n".join(logs.output))
        self.assertNotIn("Unsafe_Pkg", str(raised.exception))

    def test_formatter_switch_preserves_default_dispatch(self):
        self.assertNotIsInstance(SafetyFormatter("screen").format, CycloneDxReport)
        self.assertIsInstance(SafetyFormatter("cyclonedx").format, CycloneDXReport)
        self.assertIsInstance(SafetyFormatter("cyclonedx-json").format, CycloneDXReport)
        self.assertIsInstance(SafetyFormatter("cyclonedx@1.5").format, CycloneDXReport)

    def test_build_purl_is_case_sensitive_and_keeps_namespace(self):
        self.assertEqual(
            "pkg:pypi/Acme/Widget_Pkg@1.0",
            build_purl("Acme/Widget_Pkg", "1.0"),
        )
        self.assertEqual(
            "pkg:pypi/Foo_Bar",
            build_purl("Foo_Bar"),
        )
