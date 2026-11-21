"""Anonymised Microsoft Graph payloads, shaped like real Intune responses."""

WINDOWS_PC = {
    "id": "0f6e1a2b-0000-4000-8000-000000000001",
    "deviceName": "PC-COMPTA-04",
    "operatingSystem": "Windows",
    "osVersion": "10.0.22631.4317",
    "model": "Latitude 5440",
    "manufacturer": "Dell Inc.",
    "serialNumber": "ABC1234",
    "userPrincipalName": "j.martin@contoso.onmicrosoft.com",
    "complianceState": "compliant",
    "isEncrypted": True,
    "lastSyncDateTime": "2026-11-20T08:15:00Z",
    "managedDeviceOwnerType": "company",
    "androidSecurityPatchLevel": None,
    "azureADDeviceId": "ignored-field",
}

IPHONE = {
    "id": "0f6e1a2b-0000-4000-8000-000000000002",
    "deviceName": "iPhone de J. Martin",
    "operatingSystem": "iOS",
    "osVersion": "16.7.10",
    "model": "iPhone 12",
    "manufacturer": "Apple",
    "complianceState": "noncompliant",
    "isEncrypted": True,
    "lastSyncDateTime": "2026-11-19T18:00:00Z",
    "managedDeviceOwnerType": "personal",
}

ANDROID_NEVER_SYNCED = {
    "id": "0f6e1a2b-0000-4000-8000-000000000003",
    "deviceName": "Galaxy-Stock",
    "operatingSystem": "Android",
    "osVersion": "14",
    "androidSecurityPatchLevel": "2026-09-01",
    "lastSyncDateTime": "0001-01-01T00:00:00Z",
}

INVALID_DEVICE = {"id": "", "deviceName": "no id"}

FIREFOX = {"id": "app-firefox", "displayName": "Mozilla Firefox (x64 fr)", "version": "128.0.3",
           "publisher": "Mozilla", "platform": "windows", "deviceCount": 1}
SEVEN_ZIP = {"id": "app-7zip", "displayName": "7-Zip 19.00 (x64)", "version": "19.00",
             "publisher": "Igor Pavlov", "platform": "windows", "deviceCount": 1}
UNUSED_APP = {"id": "app-unused", "displayName": "Old Tool", "version": "1.0", "deviceCount": 0}
INVALID_APP = {"id": "app-bad", "displayName": ""}
