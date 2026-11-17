from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from io import StringIO
from typing import Any, Dict, Iterable, List, Optional, Set, TextIO, Tuple
from urllib.parse import quote

from packaging.utils import canonicalize_name

from safety.errors import CycloneDxComponentError, CycloneDxOutputError
from safety.formatter import FormatterAPI
from safety.meta import get_version
from safety.models import Package, SafetyRequirement, Vulnerability
from safety.models.requirements import is_pinned_requirement

LOG = logging.getLogger(__name__)

CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"
CYCLONEDX_SPEC_VERSION = "1.5"
ROOT_BOM_REF = "urn:safety:root"
TRANSITIVE_GROUP_BOM_REF = "urn:safety:scope:transitive"
UNKNOWN = "unknown"


@dataclass
class _Component:
    name: str
    version: str
    purl: str
    bom_ref: str
    missing_metadata: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)
    scope: Optional[str] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    synthetic: bool = False

    @property
    def key(self) -> Tuple[str, str, str]:
        return self.name, self.version, self.purl


def _text(value: Any, default: str = UNKNOWN) -> str:
    if value is None:
        return default

    value_str = str(value)
    if not value_str.strip():
        return default

    return value_str


def _requirement_version(requirement: Optional[SafetyRequirement]) -> Optional[str]:
    if not requirement or not is_pinned_requirement(requirement.specifier):
        return None

    return next(iter(requirement.specifier)).version


def _component_version(
    package: Package, requirement: Optional[SafetyRequirement]
) -> Tuple[str, bool]:
    version = _requirement_version(requirement)
    if version:
        return version, False

    package_version = _text(package.version)
    return package_version, package_version == UNKNOWN


def _encode_purl_segment(value: str) -> str:
    return quote(value, safe="")


def build_purl(name: str, version: Optional[str] = None) -> str:
    """
    Build a package URL while preserving package-name case and namespace.

    The namespace is represented by slash-separated path segments. Each segment
    is percent-encoded independently so separators and case remain intact.
    """
    name = _text(name)
    namespace: Optional[str] = None

    if "/" in name:
        namespace, name = name.rsplit("/", 1)

    encoded_name = _encode_purl_segment(_text(name))
    path = encoded_name

    if namespace:
        encoded_namespace = "/".join(
            _encode_purl_segment(segment) for segment in namespace.split("/") if segment
        )
        if encoded_namespace:
            path = f"{encoded_namespace}/{encoded_name}"

    purl = f"pkg:pypi/{path}"
    if version and version != UNKNOWN:
        purl = f"{purl}@{_encode_purl_segment(version)}"

    return purl


def _safe_source(value: Any) -> str:
    return _text(value)


def _new_component(
    package: Package, requirement: Optional[SafetyRequirement]
) -> _Component:
    raw_name = requirement.name if requirement else package.name
    name = _text(raw_name)
    version, version_missing = _component_version(package, requirement)
    requirement_source = requirement.found if requirement else None
    source = _safe_source(requirement_source or package.found)

    missing_metadata = set()
    if name == UNKNOWN:
        missing_metadata.add("name")
    if version_missing:
        missing_metadata.add("version")
    if source == UNKNOWN:
        missing_metadata.add("source")

    purl = build_purl(name, version)

    return _Component(
        name=name,
        version=version,
        purl=purl,
        bom_ref=purl,
        missing_metadata=missing_metadata,
        sources={source},
    )


def _add_component(
    components: Dict[Tuple[str, str, str], _Component],
    package: Package,
    requirement: Optional[SafetyRequirement],
) -> _Component:
    component = _new_component(package, requirement)
    existing = components.get(component.key)

    if existing:
        existing.missing_metadata.update(component.missing_metadata)
        existing.sources.update(component.sources)
        return existing

    components[component.key] = component
    return component


def _collect_components(
    packages: Iterable[Package],
) -> Dict[Tuple[str, str, str], _Component]:
    components: Dict[Tuple[str, str, str], _Component] = {}

    for package in packages:
        requirements = list(package.requirements)
        if not requirements:
            _add_component(components, package, None)
            continue

        for requirement in requirements:
            _add_component(components, package, requirement)

    return components


def _vulnerability_name(vulnerability: Vulnerability) -> str:
    requirement = vulnerability.analyzed_requirement
    if requirement:
        return _text(requirement.name)

    if vulnerability.pkg:
        return _text(vulnerability.pkg.name)

    return _text(vulnerability.package_name)


def _vulnerability_version(vulnerability: Vulnerability) -> str:
    analyzed_version = _text(vulnerability.analyzed_version)
    if analyzed_version != UNKNOWN:
        return analyzed_version

    requirement_version = _requirement_version(vulnerability.analyzed_requirement)
    if requirement_version:
        return requirement_version

    if vulnerability.pkg:
        return _text(vulnerability.pkg.version)

    return UNKNOWN


def _matching_components(
    components: Iterable[_Component], vulnerability: Vulnerability
) -> List[_Component]:
    target_name = canonicalize_name(_vulnerability_name(vulnerability))
    candidates = [
        component
        for component in components
        if canonicalize_name(component.name) == target_name
    ]
    target_version = _vulnerability_version(vulnerability)

    if target_version != UNKNOWN:
        exact = [
            component for component in candidates if component.version == target_version
        ]
        if exact:
            return exact

    return candidates


def _vulnerability_sort_key(vulnerability: Vulnerability) -> Tuple[str, ...]:
    specs = vulnerability.vulnerable_spec
    if isinstance(specs, (set, list, tuple)):
        spec_values = tuple(sorted(str(spec) for spec in specs))
    elif specs is None:
        spec_values = ()
    else:
        spec_values = (str(specs),)

    return (
        canonicalize_name(_vulnerability_name(vulnerability)),
        _vulnerability_version(vulnerability),
        _text(getattr(vulnerability, "vulnerability_id", "")),
        *spec_values,
    )


def _attach_vulnerabilities(
    components: Dict[Tuple[str, str, str], _Component],
    vulnerabilities: Iterable[Vulnerability],
) -> None:
    for vulnerability in sorted(vulnerabilities, key=_vulnerability_sort_key):
        matches = _matching_components(components.values(), vulnerability)

        if not matches:
            package = vulnerability.pkg
            requirement = vulnerability.analyzed_requirement
            if package:
                component = _add_component(components, package, requirement)
                matches = [component]

        for component in matches:
            component.vulnerabilities.append(vulnerability)
            if component.scope is None:
                component.scope = (
                    "transitive" if vulnerability.is_transitive else "direct"
                )
            elif vulnerability.is_transitive is False:
                component.scope = "direct"

    for component in components.values():
        if component.scope is None:
            component.scope = "direct"


def _sorted_sources(component: _Component) -> List[str]:
    return sorted(source for source in component.sources if source != UNKNOWN)


def _component_properties(component: _Component) -> List[Dict[str, str]]:
    properties = [
        {"name": "safety:dependency-scope", "value": component.scope or "direct"}
    ]

    sources = sorted(component.sources)
    for source in sources:
        properties.append({"name": "safety:declaration-file", "value": source})

    if component.missing_metadata:
        properties.append(
            {
                "name": "safety:missing-metadata",
                "value": ",".join(sorted(component.missing_metadata)),
            }
        )

    return properties


def _component_to_dict(component: _Component, index: int) -> Dict[str, Any]:
    fields = {
        "type": "library",
        "bom-ref": component.bom_ref,
        "name": component.name,
        "version": component.version,
        "purl": component.purl,
    }

    for field_name, value in fields.items():
        if not isinstance(value, str) or not value:
            raise CycloneDxComponentError(index, field_name)

    if not component.purl.startswith("pkg:"):
        raise CycloneDxComponentError(index, "purl")

    result: Dict[str, Any] = dict(fields)
    sources = _sorted_sources(component)
    if sources:
        result["evidence"] = {
            "occurrences": [{"location": source} for source in sources]
        }

    result["properties"] = _component_properties(component)
    return result


def _cvss_severity(score: Optional[float], fallback: Any = None) -> str:
    if fallback:
        normalized = str(fallback).lower()
        if normalized in {"critical", "high", "medium", "low", "info", "none"}:
            return normalized

    if score is None:
        return UNKNOWN
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _score(value: Any) -> Optional[float]:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None

    if score != score or score in (float("inf"), float("-inf")):
        return None

    return score


def _rating_method(vector: Any, default: str) -> str:
    vector_str = _text(vector, "")
    if vector_str.startswith("CVSS:3.1"):
        return "CVSSv31"
    if vector_str.startswith("CVSS:3.0"):
        return "CVSSv3"
    return default


def _vulnerability_ratings(vulnerability: Vulnerability) -> List[Dict[str, Any]]:
    cve = getattr(vulnerability, "CVE", None)
    if not cve:
        return []

    source_name = _text(getattr(cve, "name", None), "Safety")
    ratings = []

    for method, cvss in (
        ("CVSSv2", getattr(cve, "cvssv2", None)),
        ("CVSSv3", getattr(cve, "cvssv3", None)),
    ):
        if not cvss or not hasattr(cvss, "get"):
            continue

        score = _score(cvss.get("base_score"))
        if score is None:
            continue

        rating = {
            "source": {"name": source_name},
            "score": score,
            "severity": _cvss_severity(score, cvss.get("base_severity")),
            "method": _rating_method(cvss.get("vector_string"), method),
        }
        vector = cvss.get("vector_string")
        if vector:
            rating["vector"] = str(vector)
        ratings.append(rating)

    return ratings


def _rfc3339(value: Any) -> Optional[str]:
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    else:
        value_str = str(value).strip()
        normalized = value_str[:-1] + "+00:00" if value_str.endswith("Z") else value_str
        parsed = None
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            for date_format in ("%Y-%b-%d", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(value_str, date_format)
                    break
                except ValueError:
                    continue

        if parsed is None:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _vulnerability_id(vulnerability: Vulnerability) -> str:
    cve = getattr(vulnerability, "CVE", None)
    cve_name = _text(getattr(cve, "name", None), "")
    if cve_name.upper().startswith("CVE-"):
        return cve_name

    vulnerability_id = _text(getattr(vulnerability, "vulnerability_id", None), "")
    if vulnerability_id:
        return vulnerability_id

    return "SAFETY-UNKNOWN"


def _vulnerability_bom_ref(vulnerability: Vulnerability, component: _Component) -> str:
    specs = vulnerability.vulnerable_spec
    if isinstance(specs, (set, list, tuple)):
        spec_value = ",".join(sorted(str(spec) for spec in specs))
    else:
        spec_value = str(specs)

    identity = "|".join(
        (
            _vulnerability_id(vulnerability),
            component.bom_ref,
            _vulnerability_version(vulnerability),
            spec_value,
        )
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"urn:safety:vulnerability:{digest}"


def _vulnerability_declaration_file(
    vulnerability: Vulnerability, component: _Component
) -> str:
    requirement = vulnerability.analyzed_requirement
    if requirement and requirement.found:
        return _safe_source(requirement.found)

    sources = _sorted_sources(component)
    if sources:
        return sources[0]

    return UNKNOWN


def _vulnerability_to_dict(
    vulnerability: Vulnerability, component: _Component
) -> Dict[str, Any]:
    vulnerability_id = _vulnerability_id(vulnerability)
    declaration_file = _vulnerability_declaration_file(vulnerability, component)
    result: Dict[str, Any] = {
        "bom-ref": _vulnerability_bom_ref(vulnerability, component),
        "id": vulnerability_id,
        "source": {"name": "Safety"},
    }

    ratings = _vulnerability_ratings(vulnerability)
    if ratings:
        result["ratings"] = ratings

    advisory = _text(getattr(vulnerability, "advisory", None), "")
    if advisory:
        result["description"] = advisory

    fixed_versions = sorted(
        str(version)
        for version in (getattr(vulnerability, "fixed_versions", None) or [])
    )
    if fixed_versions:
        result["recommendation"] = "Upgrade to one of: " + ", ".join(fixed_versions)

    published = _rfc3339(getattr(vulnerability, "published_date", None))
    if published:
        result["published"] = published

    advisories = []
    resources = getattr(vulnerability, "resources", None) or []
    for resource in sorted(
        {
            str(resource)
            for resource in resources
            if resource and not any(char.isspace() for char in str(resource))
        }
    ):
        advisories.append({"url": resource})
    if advisories:
        result["advisories"] = advisories

    affect: Dict[str, Any] = {"ref": component.bom_ref}
    if component.version != UNKNOWN:
        affect["versions"] = [{"version": component.version}]
    result["affects"] = [affect]

    properties = [
        {
            "name": "safety:vulnerability-id",
            "value": _text(vulnerability.vulnerability_id),
        },
        {"name": "safety:package-name", "value": component.name},
        {"name": "safety:analyzed-version", "value": component.version},
        {"name": "safety:declaration-file", "value": declaration_file},
        {
            "name": "safety:ignored",
            "value": "true" if vulnerability.ignored else "false",
        },
    ]

    specs = vulnerability.vulnerable_spec
    if isinstance(specs, (set, list, tuple)):
        spec_values = sorted(str(spec) for spec in specs)
    elif specs is None:
        spec_values = []
    else:
        spec_values = [str(specs)]

    for spec in spec_values:
        properties.append({"name": "safety:vulnerable-spec", "value": spec})

    result["properties"] = properties
    return result


def _deduplicate_vulnerabilities(
    components: Iterable[_Component],
) -> List[Tuple[Vulnerability, _Component]]:
    seen = set()
    result = []

    for component in components:
        for vulnerability in component.vulnerabilities:
            specs = vulnerability.vulnerable_spec
            if isinstance(specs, (set, list, tuple)):
                spec_value = tuple(sorted(str(spec) for spec in specs))
            else:
                spec_value = (str(specs),)

            key = (
                component.bom_ref,
                _vulnerability_id(vulnerability),
                _vulnerability_version(vulnerability),
                spec_value,
            )
            if key in seen:
                continue

            seen.add(key)
            result.append((vulnerability, component))

    return sorted(
        result,
        key=lambda item: (
            item[1].bom_ref,
            _vulnerability_id(item[0]),
            _vulnerability_version(item[0]),
        ),
    )


def _synthetic_transitive_group() -> _Component:
    return _Component(
        name="safety-scope-transitive",
        version=UNKNOWN,
        purl=build_purl("safety-scope-transitive"),
        bom_ref=TRANSITIVE_GROUP_BOM_REF,
        scope="transitive",
        synthetic=True,
    )


def _component_dicts(
    components: List[_Component],
) -> Iterable[Dict[str, Any]]:
    for index, component in enumerate(components):
        yield _component_to_dict(component, index)


def _dependencies(
    components: List[_Component],
) -> Tuple[List[Dict[str, Any]], List[_Component]]:
    actual_components = [
        component for component in components if not component.synthetic
    ]
    direct = sorted(
        (
            component
            for component in actual_components
            if component.scope != "transitive"
        ),
        key=lambda component: component.bom_ref,
    )
    transitive = sorted(
        (
            component
            for component in actual_components
            if component.scope == "transitive"
        ),
        key=lambda component: component.bom_ref,
    )
    extra_components: List[_Component] = []
    dep_map: Dict[str, List[str]] = {
        component.bom_ref: [] for component in actual_components
    }
    root_depends = [component.bom_ref for component in direct]

    if transitive:
        if len(direct) == 1:
            dep_map[direct[0].bom_ref] = [component.bom_ref for component in transitive]
        else:
            group = _synthetic_transitive_group()
            extra_components.append(group)
            root_depends.append(group.bom_ref)
            dep_map[group.bom_ref] = [component.bom_ref for component in transitive]

    dependencies = [{"ref": ROOT_BOM_REF, "dependsOn": sorted(root_depends)}]
    dependencies.extend(
        {"ref": ref, "dependsOn": sorted(depends)}
        for ref, depends in sorted(dep_map.items())
    )
    return dependencies, extra_components


def _metadata(components: List[_Component], vulnerability_count: int) -> Dict[str, Any]:
    actual_components = [
        component for component in components if not component.synthetic
    ]
    degraded = [
        component for component in actual_components if component.missing_metadata
    ]
    missing_version = sum(
        "version" in component.missing_metadata for component in actual_components
    )
    missing_source = sum(
        "source" in component.missing_metadata for component in actual_components
    )
    missing_name = sum(
        "name" in component.missing_metadata for component in actual_components
    )

    return {
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "Safety",
                    "version": get_version(),
                }
            ]
        },
        "component": {
            "type": "application",
            "bom-ref": ROOT_BOM_REF,
            "name": "safety-scan",
            "version": UNKNOWN,
        },
        "properties": [
            {"name": "safety:component-count", "value": str(len(actual_components))},
            {
                "name": "safety:degraded-components",
                "value": str(len(degraded)),
            },
            {
                "name": "safety:missing-version-components",
                "value": str(missing_version),
            },
            {
                "name": "safety:missing-source-components",
                "value": str(missing_source),
            },
            {
                "name": "safety:missing-name-components",
                "value": str(missing_name),
            },
            {
                "name": "safety:vulnerability-count",
                "value": str(vulnerability_count),
            },
        ],
    }


def _write_json(stream: TextIO, value: Any) -> None:
    stream.write(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
    )


def _write_array(stream: TextIO, values: Iterable[Dict[str, Any]]) -> None:
    stream.write("[")
    first = True
    for value in values:
        if not first:
            stream.write(",")
        _write_json(stream, value)
        first = False
    stream.write("]")


class CycloneDxReport(FormatterAPI):
    """
    CycloneDX 1.5 JSON report writer.

    Use ``write_vulnerabilities`` with an output stream to keep memory usage
    bounded for large inventories. ``render_vulnerabilities`` remains available
    for FormatterAPI compatibility and materializes the document in a StringIO.
    """

    def write_vulnerabilities(
        self,
        stream: TextIO,
        announcements: List[Dict[str, Any]],
        vulnerabilities: List[Vulnerability],
        remediations: Dict[str, Any],
        full: bool,
        packages: List[Package],
        fixes: Iterable = (),
    ) -> None:
        LOG.info("Starting CycloneDX report generation")
        try:
            components = _collect_components(packages)
            _attach_vulnerabilities(components, vulnerabilities)

            sorted_components = sorted(
                components.values(),
                key=lambda component: component.key,
            )
            dependencies, extra_components = _dependencies(sorted_components)
            sorted_components.extend(extra_components)
            sorted_components = sorted(
                sorted_components,
                key=lambda component: (component.synthetic, component.key),
            )

            component_dicts = list(_component_dicts(sorted_components))
            vulnerability_pairs = _deduplicate_vulnerabilities(sorted_components)
            vulnerability_dicts = [
                _vulnerability_to_dict(vulnerability, component)
                for vulnerability, component in vulnerability_pairs
            ]
            metadata = _metadata(sorted_components, len(vulnerability_dicts))

            stream.write("{")
            stream.write(
                f'"$schema":{json.dumps(CYCLONEDX_SCHEMA)},'
                f'"bomFormat":"CycloneDX",'
                f'"specVersion":{json.dumps(CYCLONEDX_SPEC_VERSION)},'
                f'"version":1,'
                f'"metadata":'
            )
            _write_json(stream, metadata)
            stream.write(',"components":')
            _write_array(stream, component_dicts)
            stream.write(',"dependencies":')
            _write_array(stream, dependencies)
            stream.write(',"vulnerabilities":')
            _write_array(stream, vulnerability_dicts)
            stream.write("}\n")
            stream.flush()
        except CycloneDxComponentError as error:
            LOG.error(
                "CycloneDX report generation failed at component[%s]: %s",
                error.index,
                error.field,
            )
            raise
        except CycloneDxOutputError:
            LOG.error("CycloneDX report generation failed: output error")
            raise
        except Exception:
            LOG.error("CycloneDX report generation failed: output error")
            raise CycloneDxOutputError() from None

        LOG.info(
            "Finished CycloneDX report generation: components=%s vulnerabilities=%s",
            len(component_dicts),
            len(vulnerability_dicts),
        )

    def render_vulnerabilities(
        self,
        announcements: List[Dict[str, Any]],
        vulnerabilities: List[Vulnerability],
        remediations: Dict[str, Any],
        full: bool,
        packages: List[Package],
        fixes: Iterable = (),
    ) -> str:
        stream = StringIO()
        self.write_vulnerabilities(
            stream,
            announcements,
            vulnerabilities,
            remediations,
            full,
            packages,
            fixes,
        )
        return stream.getvalue()

    def render_licenses(
        self, announcements: List[Dict[str, Any]], licenses: List[Dict[str, Any]]
    ) -> None:
        return None

    def render_announcements(self, announcements: List[Dict[str, Any]]) -> None:
        return None


CycloneDXReport = CycloneDxReport
