
from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

from dissect.esedb import EseDB
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.exceptions import UnsupportedPluginError

if TYPE_CHECKING:
    from dissect.target.target import Target


COMPUTERS_MAP = {
    'sAMAccountName': "ATTm590045",
    'dNSHostName': "ATTm590443",
    'operatingSystem': "ATTm590187",
    'lastLogon': "ATTq589876",
    'userAccountControl': "ATTj589832",
    'whenCreated': "ATTl131074",
    'objectSid': "ATTr589970",
    'description': "ATTm13",
}

PW_POLICY_MAP = {
    "standard": {
        "name": "ATTm589825",
        "ms-DS-MachineAccountQuota": "ATTj591235",
    },
    # AD wide password policy attributes
    "ad_wide": {
        "minPwdLength": "ATTj589903",
        "minPwdAge": "ATTq589902",
        "maxPwdAge": "ATTq589898",
        "lockoutThreshold": "ATTj589897",
        "lockoutDuration": "ATTq589884",
        "lockoutObservationWindow": "ATTq589885",
        "pwdHistoryLength": "ATTj589919",
    },
    # Fine-grained password policy attributes
    "fine_grained": {
        "msDS-MinimumPasswordLength": "ATTj591837",
        "msDS-MinimumPasswordAge": "ATTq591836",
        "msDS-MaximumPasswordAge": "ATTq591835",
        "msDS-LockoutThreshold": "ATTj591843",
        "msDS-LockoutDuration": "ATTq591842",
        "msDS-LockoutObservationWindow": "ATTq591841",
        "msDS-PasswordHistoryLength": "ATTj591838",
    },
}

ADPasswordPolicyRecord = TargetRecordDescriptor(
    "windows/ad/password_policy",
    [
        ("string", "applied_to"),
        ("varint", "machine_account_quota"),
        ("varint", "min_password_length"),
        ("string", "min_password_age"),
        ("string", "max_password_age"),
        ("varint", "lockout_threshold"),
        ("string", "lockout_duration"),
        ("string", "lockout_observation_window"),
        ("varint", "password_history_length"),
    ],
)

ADComputerRecord = TargetRecordDescriptor(
    "windows/ad/computers",
    [
        ("string", "samaccountname"),
        ("string", "dnshostname"),
        ("string", "operating_system"),
        ("string", "last_logon"),
        ("string", "uac"),
        ("string", "when_created"),
        ("string", "objectsid"),
        ("string", "description"),
    ],
)


class NTDSPlugin(Plugin):
    __namespace__ = "ntds"

    NTDS_DB_REG_PATH = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
    NTDS_DB_REG_KEY = "DSA Database file"

    def __init__(self, target: Target):
        super().__init__(target)
        self.NTDS_DB_PATH = self._get_ntds_path()

    def check_compatible(self) -> None:
        if not self.target.fs.exists(self.NTDS_DB_PATH):
            raise UnsupportedPluginError

    def _get_ntds_path(self) -> str:
        try:
            ntds_path = self.target.registry.key(
                self.NTDS_DB_REG_PATH).value(self.NTDS_DB_REG_KEY).value
            return ntds_path
        except Exception as e:
            print(e)

    def lookup_ldap_attirbutes(self, attribute_names: [str]) -> dict:
        attribute_mapping = {}
        col_with_id = "ATTc131102"
        col_with_attr = "ATTm131532"
        datatable = self.db.table("datatable")
        for i in datatable.records():
            f = i.get(col_with_id)
            g = i.get(col_with_attr)

            if not (f and g):
                continue

            if g not in attribute_names:
                continue

            attribute_mapping[g] = f

            return attribute_mapping

    @export(output="record")
    def computers(self) -> Iterator[ADComputerRecord]:
        """Return all AD-joined computers found in the NTDS database.
        """
        db= EseDB(self.target.fs.open(self.NTDS_DB_PATH))
        datatable= db.table("datatable")

        for record in datatable.records():
            # A record should have at least these two to be a computer record
            if not (record.get(COMPUTERS_MAP['dNSHostName']) and record.get(COMPUTERS_MAP['sAMAccountName'])):
                continue

            output= {}

            for name, id in COMPUTERS_MAP.items():
                output[name]= record.get(id)

            print(record.get("ATTm131532"))

            yield ADComputerRecord(
                _target = self.target,
                samaccountname = output['sAMAccountName'],
                dnshostname = output['dNSHostName'],
                operating_system = output['operatingSystem'],
                last_logon = output['lastLogon'],
                uac = output['userAccountControl'],
                when_created = output['whenCreated'],
                objectsid = output['objectSid'],
                description = output['description']
            )

    @export(output="record")
    def password_policy(self) -> Iterator[ADPasswordPolicyRecord]:
        """Return the domain-wide and fine-grained password policy.
        """
        db = EseDB(self.target.fs.open(self.NTDS_DB_PATH))
        datatable = db.table("datatable")

        for record in datatable.records():
            ad_wide_policy = record.get(
                PW_POLICY_MAP['ad_wide']['minPwdLength']
            )
            fine_grained_policy = record.get(
                PW_POLICY_MAP['fine_grained']['msDS-MinimumPasswordLength']
            )

            if not (ad_wide_policy or fine_grained_policy):
                continue

            output = {}

            for key, value in PW_POLICY_MAP["standard"].items():
                output[key] = record.get(value)

            if ad_wide_policy:
                for key, value in PW_POLICY_MAP["ad_wide"].items():
                    output[key] = record.get(value)

                yield ADPasswordPolicyRecord(
                    _target=self.target,
                    applied_to=output['name'],
                    machine_account_quota=output['ms-DS-MachineAccountQuota'],
                    min_password_length=output['minPwdLength'],
                    min_password_age=convert_time(output['minPwdAge']),
                    max_password_age=convert_time(output['maxPwdAge']),
                    lockout_threshold=output['lockoutThreshold'],
                    lockout_duration=convert_time(output['lockoutDuration']),
                    lockout_observation_window=convert_time(output['lockoutObservationWindow']),
                    password_history_length=output['pwdHistoryLength'],
                )
                if fine_grained_policy:
                    for key, value in PW_POLICY_MAP["fine_grained"].items():
                        output[key] = record.get(value)

                    yield ADPasswordPolicyRecord(
                        _target=self.target,
                        applied_to=output['name'],
                        machine_account_quota=output['ms-DS-MachineAccountQuota'],
                        min_password_length=output["msDS-MinimumPasswordLength"],
                        min_password_age=convert_time(output["msDS-MinimumPasswordAge"]),
                        max_password_age=convert_time(output["msDS-MaximumPasswordAge"]),
                        lockout_threshold=output["msDS-LockoutThreshold"],
                        lockout_duration=convert_time(output["msDS-LockoutDuration"]),
                        lockout_observation_window=convert_time(
                        output["msDS-LockoutObservationWindow"]),
                        password_history_length=output["msDS-PasswordHistoryLength"],
                    )


def convert_time(time):
    # Handle special cases
    if time == 0:
        return None
    if time == -9223372036854775808:
        return "Not Set"

    # Convert the time to seconds (abs value to handle negative times)
    sec = abs(time) // 10000000

    # Calculate days, hours, minutes, and seconds
    days, remainder= divmod(sec, 86400)  # 86400 seconds in a day
    hrs, remainder= divmod(remainder, 3600)  # 3600 seconds in an hour
    mins, sec= divmod(remainder, 60)  # 60 seconds in a minute

    # Build the result using f-strings for readability
    result= []
    if days:
        result.append(f"{days}d")
    if hrs:
        result.append(f"{hrs}h")
    if mins:
        result.append(f"{mins}m")

    # If no time units were added, it means time is less than a minute.
    if not result:
        result.append(f"{sec}s")

    return ' '.join(result)
