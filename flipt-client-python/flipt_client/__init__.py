from pydantic import BaseModel
import ctypes
import logging
import os
import platform
import threading
import warnings
from datetime import datetime, timedelta
from typing import Callable, List, Optional

from .errors import FliptError, ValidationError, EvaluationError

from .models import (
    AuthenticationLease,
    AuthUpdateResult,
    BatchEvaluationResponse,
    BatchResult,
    BooleanEvaluationResponse,
    BooleanResult,
    ClientOptions,
    EvaluationRequest,
    FlagList,
    ListFlagsResult,
    VariantEvaluationResponse,
    VariantResult,
    model_to_json,
    model_from_json,
)

logger = logging.getLogger(__name__)


class InternalEvaluationRequest(BaseModel):
    namespace_key: str
    flag_key: str
    entity_id: str
    context: dict


class FliptClient:
    """Main client for interacting with Flipt feature flag engine."""

    _EXPIRY_BUFFER = timedelta(seconds=30)
    _MIN_RETRY_DELAY = timedelta(seconds=5)

    def __init__(
        self,
        opts: ClientOptions = ClientOptions(),
        authentication_provider: Optional[Callable[[], AuthenticationLease]] = None,
    ):
        if authentication_provider is not None and opts.authentication is not None:
            raise ValidationError(
                "Cannot set both authentication (in opts) and authentication_provider"
            )

        self._authentication_provider = authentication_provider
        self._auth_timer = None  # type: Optional[threading.Timer]
        self._closed = threading.Event()
        self._consecutive_auth_failures = 0
        self._max_auth_retries = 0
        self._current_expiry = None  # type: Optional[datetime]

        # If a provider is given, call it to get the initial lease
        if self._authentication_provider is not None:
            initial_lease = self._authentication_provider()
            opts = opts.copy() if hasattr(opts, "copy") else opts.model_copy()
            opts.authentication = initial_lease.strategy
            self._current_expiry = initial_lease.get_expires_at()
            max_retries = initial_lease.get_max_retries()
            self._max_auth_retries = max_retries if max_retries is not None else 0

        namespace = opts.namespace or "default"
        # Mapping of platform-architecture combinations to their respective library file paths
        lib_files = {
            "Darwin-x86_64": "darwin_x86_64/libfliptengine.dylib",
            "Darwin-arm64": "darwin_aarch64/libfliptengine.dylib",
            "Darwin-aarch64": "darwin_aarch64/libfliptengine.dylib",
            "Linux-x86_64": "linux_x86_64/libfliptengine.so",
            "Linux-arm64": "linux_aarch64/libfliptengine.so",
            "Linux-aarch64": "linux_aarch64/libfliptengine.so",
            "Windows-x86_64": "windows_x86_64/fliptengine.dll",
        }

        platform_name = platform.system()
        arch = platform.machine()
        key = f"{platform_name}-{arch}"

        libfile = lib_files.get(key)

        if not libfile:
            raise FliptError(f"Unsupported platform/processor: {platform_name}/{arch}")

        # Get the absolute path to the engine library from the ../ext directory
        engine_library_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), f"../ext/{libfile}"
        )

        if not os.path.exists(engine_library_path):
            raise FliptError(
                f"The engine library could not be found at the path: {engine_library_path}"
            )

        self.namespace_key = namespace

        self.ffi_core = ctypes.CDLL(engine_library_path)

        self.ffi_core.initialize_engine.restype = ctypes.c_void_p
        self.ffi_core.destroy_engine.argtypes = [ctypes.c_void_p]

        self.ffi_core.evaluate_variant.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.ffi_core.evaluate_variant.restype = ctypes.POINTER(ctypes.c_char_p)

        self.ffi_core.evaluate_boolean.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.ffi_core.evaluate_boolean.restype = ctypes.POINTER(ctypes.c_char_p)

        self.ffi_core.evaluate_batch.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.ffi_core.evaluate_batch.restype = ctypes.POINTER(ctypes.c_char_p)

        self.ffi_core.list_flags.argtypes = [ctypes.c_void_p]
        self.ffi_core.list_flags.restype = ctypes.POINTER(ctypes.c_char_p)

        self.ffi_core.destroy_string.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
        self.ffi_core.destroy_string.restype = ctypes.c_void_p

        self.ffi_core.get_snapshot.argtypes = [ctypes.c_void_p]
        self.ffi_core.get_snapshot.restype = ctypes.POINTER(ctypes.c_char_p)

        self.ffi_core.update_authentication.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
        ]
        self.ffi_core.update_authentication.restype = ctypes.POINTER(ctypes.c_char_p)

        client_opts_serialized = model_to_json(opts, exclude_none=True).encode("utf-8")

        self.engine = self.ffi_core.initialize_engine(client_opts_serialized)

        # Start auth refresh scheduler for expiring leases
        if self._authentication_provider is not None and self._current_expiry is not None:
            self._schedule_next_auth_refresh()

    def close(self):
        self._closed.set()
        if hasattr(self, "_auth_timer") and self._auth_timer is not None:
            self._auth_timer.cancel()
            self._auth_timer = None
        if hasattr(self, "engine") and self.engine is not None:
            self.ffi_core.destroy_engine(self.engine)
            self.engine = None

    def _schedule_next_auth_refresh(self):
        """Schedule the next authentication refresh based on the current expiry."""
        if self._closed.is_set() or self._current_expiry is None:
            return

        now = datetime.now(self._current_expiry.tzinfo)
        delay = (self._current_expiry - self._EXPIRY_BUFFER - now).total_seconds()
        delay = max(delay, self._MIN_RETRY_DELAY.total_seconds())

        self._auth_timer = threading.Timer(delay, self._refresh_authentication)
        self._auth_timer.daemon = True
        self._auth_timer.start()

    def _refresh_authentication(self):
        """Refresh authentication by calling the provider and updating the engine."""
        if self._closed.is_set():
            return

        try:
            lease = self._authentication_provider()
            if self._closed.is_set():
                return

            auth_json = model_to_json(
                lease.strategy, exclude_none=True
            ).encode("utf-8")
            response = self.ffi_core.update_authentication(self.engine, auth_json)
            bytes_returned = ctypes.cast(response, ctypes.c_char_p).value
            result = model_from_json(AuthUpdateResult, bytes_returned)
            self.ffi_core.destroy_string(response)

            if result.status != "success":
                self._consecutive_auth_failures += 1
                logger.warning(
                    "Failed to update engine authentication: %s",
                    result.error_message or "Unknown error",
                )
            else:
                self._consecutive_auth_failures = 0
                self._current_expiry = lease.get_expires_at()
        except Exception as e:
            self._consecutive_auth_failures += 1
            logger.warning("Failed to refresh authentication: %s", e)

        if self._closed.is_set():
            return
        if self._current_expiry is None:
            return
        if self._consecutive_auth_failures >= self._max_auth_retries:
            logger.error(
                "Authentication refresh failed after %d consecutive attempts, "
                "stopping refresh",
                self._max_auth_retries,
            )
            return

        self._schedule_next_auth_refresh()

    def evaluate_variant(
        self, flag_key: str, entity_id: str, context: Optional[dict] = None
    ) -> VariantEvaluationResponse:
        if context is None:
            context = {}
        if not flag_key or not flag_key.strip():
            raise ValidationError("flag_key cannot be empty or null")
        if not entity_id or not entity_id.strip():
            raise ValidationError("entity_id cannot be empty or null")

        response = self.ffi_core.evaluate_variant(
            self.engine,
            serialize_evaluation_request(
                self.namespace_key, flag_key, entity_id, context
            ),
        )

        bytes_returned = ctypes.cast(response, ctypes.c_char_p).value
        variant_result = model_from_json(VariantResult, bytes_returned)
        self.ffi_core.destroy_string(response)

        if variant_result.status != "success":
            raise EvaluationError(variant_result.error_message)

        return variant_result.result

    def evaluate_boolean(
        self, flag_key: str, entity_id: str, context: Optional[dict] = None
    ) -> BooleanEvaluationResponse:
        if context is None:
            context = {}
        if not flag_key or not flag_key.strip():
            raise ValidationError("flag_key cannot be empty or null")
        if not entity_id or not entity_id.strip():
            raise ValidationError("entity_id cannot be empty or null")

        response = self.ffi_core.evaluate_boolean(
            self.engine,
            serialize_evaluation_request(
                self.namespace_key, flag_key, entity_id, context
            ),
        )

        bytes_returned = ctypes.cast(response, ctypes.c_char_p).value
        boolean_result = model_from_json(BooleanResult, bytes_returned)
        self.ffi_core.destroy_string(response)

        if boolean_result.status != "success":
            raise EvaluationError(boolean_result.error_message)

        return boolean_result.result

    def evaluate_batch(
        self, requests: List[EvaluationRequest]
    ) -> BatchEvaluationResponse:
        evaluation_requests = []

        for r in requests:
            if not r.flag_key or not r.flag_key.strip():
                raise ValidationError("flag_key cannot be empty or null")
            if not r.entity_id or not r.entity_id.strip():
                raise ValidationError("entity_id cannot be empty or null")

            evaluation_requests.append(
                InternalEvaluationRequest(
                    namespace_key=self.namespace_key,
                    flag_key=r.flag_key,
                    entity_id=r.entity_id,
                    context=r.context,
                )
            )

        json_list = [
            model_to_json(evaluation_request)
            for evaluation_request in evaluation_requests
        ]
        json_string = "[" + ", ".join(json_list) + "]"

        response = self.ffi_core.evaluate_batch(
            self.engine, json_string.encode("utf-8")
        )

        bytes_returned = ctypes.cast(response, ctypes.c_char_p).value
        batch_result = model_from_json(BatchResult, bytes_returned)
        self.ffi_core.destroy_string(response)

        if batch_result.status != "success":
            raise EvaluationError(batch_result.error_message)

        return batch_result.result

    def list_flags(self) -> FlagList:
        response = self.ffi_core.list_flags(self.engine)

        bytes_returned = ctypes.cast(response, ctypes.c_char_p).value
        result = model_from_json(ListFlagsResult, bytes_returned)
        self.ffi_core.destroy_string(response)

        if result.status != "success":
            raise EvaluationError(result.error_message)

        return result.result

    def get_snapshot(self) -> str:
        """
        Returns a snapshot of the current engine state as a base64 encoded JSON string.
        """
        response = self.ffi_core.get_snapshot(self.engine)
        snapshot_bytes = ctypes.cast(response, ctypes.c_char_p).value
        if hasattr(self.ffi_core, "destroy_string"):
            self.ffi_core.destroy_string(response)
        return snapshot_bytes.decode("utf-8")

    def __del__(self):
        self.close()


def serialize_evaluation_request(
    namespace_key: str, flag_key: str, entity_id: str, context: dict
) -> str:
    if not flag_key or not flag_key.strip():
        raise ValidationError("flag_key cannot be empty or null")
    if not entity_id or not entity_id.strip():
        raise ValidationError("entity_id cannot be empty or null")

    evaluation_request = InternalEvaluationRequest(
        namespace_key=namespace_key,
        flag_key=flag_key,
        entity_id=entity_id,
        context=context,
    )

    return model_to_json(evaluation_request).encode("utf-8")


# Deprecation alias
class FliptEvaluationClient(FliptClient):
    def __init__(self, *args, **kwargs):
        warnings.warn(
            "FliptEvaluationClient is deprecated and will be removed in a future release. Use FliptClient instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
