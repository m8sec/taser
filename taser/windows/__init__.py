"""Windows-focused helpers for diagnostics and telemetry."""

from taser.windows.etw import (
    DEFAULT_PROVIDER_ACES,
    ETW_PERMISSION_DEFINITIONS,
    build_provider_report,
    edit_session_providers,
    describe_permission_catalog,
    enumerate_etw_providers,
    load_provider_requests,
    resolve_provider_for_edit,
    search_provider_by_guid,
    search_providers_by_name,
    search_providers_by_permission,
)
from taser.windows.hooks import list_processes

__all__ = [
    "DEFAULT_PROVIDER_ACES",
    "ETW_PERMISSION_DEFINITIONS",
    "build_provider_report",
    "edit_session_providers",
    "describe_permission_catalog",
    "enumerate_etw_providers",
    "load_provider_requests",
    "list_processes",
    "resolve_provider_for_edit",
    "search_provider_by_guid",
    "search_providers_by_name",
    "search_providers_by_permission",
]
