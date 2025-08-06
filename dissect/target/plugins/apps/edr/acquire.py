from __future__ import annotations

import csv
import gzip
import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

AcquireOpenHandlesRecord = TargetRecordDescriptor(
    "acquire/filesystem/acquire_open_handles",
    [
        ("path", "name"),
        ("string", "handle_type"),
        ("string", "object"),
        ("varint", "unique_process_id"),
        ("varint", "handle_value"),
        ("varint", "granted_access"),
        ("varint", "creator_back_trace_index"),
        ("varint", "object_type_index"),
        ("varint", "handle_attributes"),
        ("varint", "reserved"),
    ],
)

AcquireHashRecord = TargetRecordDescriptor(
    "acquire/filesystem/acquire_hash",
    [
        ("path", "path"),
        ("filesize", "filesize"),
        ("digest", "digest"),
    ],
)

AcquireNetstatRecord = TargetRecordDescriptor(
    "acquire/volatile/netstat",
    [
        ("string", "protocol"),
        ("string", "local_address"),
        ("string", "foreign_address"),
        ("string", "state"),
        ("varint", "pid"),
    ],
)

AcquireProcessesRecord = TargetRecordDescriptor(
    "acquire/volatile/processes",
    [
        ("string", "image_name"),
        ("varint", "pid"),
        ("string", "session_name"),
        ("varint", "session_id"),
        ("string", "mem_usage"),
        ("string", "status"),
        ("string", "username"),
        ("string", "cpu_time"),
        ("string", "window_title"),
    ],
)

AcquireProcessEnvVarsRecord = TargetRecordDescriptor(
    "acquire/volatile/process_env_vars",
    [
        ("string", "variable_name"),
        ("string", "value"),
    ],
)

class AcquirePlugin(Plugin):
    """Returns records from data collected by Acquire."""

    __namespace__ = "acquire"

    def __init__(self, target: Target):
        super().__init__(target)
        self.hash_file = target.fs.path("$metadata$/file-hashes.csv.gz")
        self.open_handles_file = target.fs.path("$metadata$/open_handles.csv.gz")
        self.netstat_file = target.fs.path("$metadata$/command-output/netstat")
        self.processes_file = target.fs.path("$metadata$/command-output/win-processes")
        self.process_env_vars_file = target.fs.path("$metadata$/command-output/win-process-env-vars")

    def check_compatible(self) -> None:
        if not any([
            self.hash_file.exists(),
            self.open_handles_file.exists(),
            self.netstat_file.exists(),
            self.processes_file.exists(),
            self.process_env_vars_file.exists()
        ]):
            raise UnsupportedPluginError("No hash file or open handles found")

    @export(record=AcquireHashRecord)
    def hashes(self) -> Iterator[AcquireHashRecord]:
        """Return file hashes collected by Acquire.

        An Acquire file container contains a file hashes csv when the hashes module was used. The content of this csv
        file is returned.
        """
        if not self.hash_file.exists():
            return

        with self.hash_file.open() as fh, gzip.open(fh, "rt") as gz_fh:
            for row in csv.DictReader(gz_fh):
                yield AcquireHashRecord(
                    path=self.target.fs.path(row["path"]),
                    filesize=row["file-size"],
                    digest=(row["md5"] or None, row["sha1"] or None, row["sha256"] or None),
                    _target=self.target,
                )

    @export(record=AcquireOpenHandlesRecord)
    def handles(self) -> Iterator[AcquireOpenHandlesRecord]:
        """Return open handles collected by Acquire.

        An Acquire file container contains an open handles csv when the handles module was used. The content of this csv
        file is returned.
        """
        if not self.open_handles_file.exists():
            return

        with self.open_handles_file.open() as fh, gzip.open(fh, "rt") as gz_fh:
            for row in csv.DictReader(gz_fh):
                if name := row.get("name"):
                    row.update({"name": self.target.fs.path(name)})
                yield AcquireOpenHandlesRecord(**row, _target=self.target)

    @export(record=AcquireNetstatRecord)
    def netstat(self) -> Iterator[AcquireNetstatRecord]:
        if not self.netstat_file.exists():
            return
        
        with self.netstat_file.open("rt") as fh:
            for row in csv.DictReader(
                f=fh,
                skipinitialspace=True,
                delimiter=" ",
                fieldnames=["Proto", "Local Address", "Foreign Address", "State", "PID"]
            ):
                # This part is messy but I could not come up with something
                # better at the time. The protocol is either TCP or UDP.
                # Since UDP has is stateless and the CSV parser does not handle
                # empty values when the format is not actually CSV, we just
                # use the "State" key in the row dict as PID, when
                # we're dealin with UDP
                if row["Proto"] == "TCP":
                    yield AcquireNetstatRecord(
                        protocol=row["Proto"],
                        local_address=row["Local Address"],
                        foreign_address=row["Foreign Address"],
                        state=row["State"],
                        pid=row["PID"],
                        _target=self.target,
                    )
                if row["Proto"] == "UDP":
                    yield AcquireNetstatRecord(
                        protocol=row["Proto"],
                        local_address=row["Local Address"],
                        foreign_address=row["Foreign Address"],
                        state=None,
                        pid=row["State"],
                        _target=self.target,
                    )

    @export(record=AcquireProcessesRecord)
    def processes(self) -> Iterator[AcquireProcessesRecord]:
        if not self.processes_file.exists():
            return

        with self.processes_file.open("rt") as fh:
            for row in csv.DictReader(f=fh):
                yield AcquireProcessesRecord(
                    image_name=row["Image Name"],
                    pid=row["PID"],
                    session_name=row["Session Name"],
                    session_id=row["Session#"],
                    mem_usage=row["Mem Usage"],
                    status=row["Status"],
                    username=row["User Name"],
                    cpu_time=row["CPU Time"],
                    window_title=row["Window Title"],
                    _target=self.target,
                )

    @export(record=AcquireProcessEnvVarsRecord)
    def process_env_vars(self) -> Iterator[AcquireProcessEnvVarsRecord]:
        if not self.process_env_vars_file.exists():
            return

        pattern = re.compile(r"(^\S+)\s+(\S.*)$")
        
        # This could contain lots of duplicate entries so lets dedup.
        unique_entries = set(self.process_env_vars_file.read_text().splitlines())
        for entry in unique_entries:
            if valid_entry := re.search(pattern, entry):
                yield AcquireProcessEnvVarsRecord(
                    variable_name=valid_entry.group(1).strip(),
                    value=valid_entry.group(2).strip(),
                    _target=self.target,
                )
            
