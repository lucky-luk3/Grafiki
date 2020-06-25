CREATE TABLE "DNSResolution"
(
    id SERIAL,
    "UtcTime" TIMESTAMPTZ,
	"QueryName" VARCHAR(255),
	"QueryStatus" VARCHAR(255),
	"QueryResults" VARCHAR(255)
);

CREATE TABLE  "DNSQuery"
(
	"QueryName" VARCHAR(255) PRIMARY KEY
);

CREATE TABLE  "Pipes"
(
	"PipeName" VARCHAR(255) PRIMARY KEY
);

CREATE TABLE  "Files"
(
	"Filename" VARCHAR(255) PRIMARY KEY,
	"OriginalFileName" VARCHAR(255),
    "CreationUtcTime" TIMESTAMPTZ,
	"Description" VARCHAR(255),
	"Company" VARCHAR(255),
	"Hashes" VARCHAR(255),
	"Signed" VARCHAR(255),
	"Signature" VARCHAR(255),
	"SignatureStatus" VARCHAR(255),
	"Product" VARCHAR(255),
	"FileVersion" VARCHAR(255)
);

CREATE TABLE  "RegistryKeys"
(
	"Key" VARCHAR(1010) PRIMARY KEY,
    "Details" VARCHAR(10010)
);

CREATE TABLE  "Processes"
(
    "ProcessGuid" VARCHAR(255) PRIMARY KEY,
    "ProcessId" INT,
    "Image" VARCHAR(255),
    "IntegrityLevel" VARCHAR(255),
    "TerminalSessionId" INT,
    "User" VARCHAR(255),
    "ComputerName" VARCHAR(255)
);

CREATE TABLE  "Users"
(
    "LogonGuid" VARCHAR(255) PRIMARY KEY,
    "Name" VARCHAR(255),
    "LogonId" VARCHAR(255),
    "TerminalSessionId" INT,
    "UserID" VARCHAR(255)
);

CREATE TABLE  "Actions"
(
    action_id SERIAL,
    "UtcTime" TIMESTAMPTZ,
    "ActionType" VARCHAR(255),
    "ProcessGuid" VARCHAR(255),
    "LogonGuid" VARCHAR(255),
    "DestinationId" VARCHAR(255),
    "ExtraInfo" VARCHAR(5550),
    "ExtraInfo2" VARCHAR(5550)
);

CREATE TABLE  "Threads"
(
    threads_id SERIAL,
    "ThreadId" VARCHAR(255),
    "ThreadNId" INT,
    "StartAddress" VARCHAR(255),
    "StartModule" VARCHAR(255),
    "StartFunction" VARCHAR(255),
    "ProcessGuid" VARCHAR(255)
);

CREATE TABLE  "Connections"
(
    "ConnectionId" VARCHAR(255),
    "Protocol" VARCHAR(255),
    "SourceIp" VARCHAR(255),
    "SourceHostname" VARCHAR(255),
    "SourcePort" VARCHAR(255),
    "DestinationIsIpv6" VARCHAR(255),
    "DestinationIp" VARCHAR(255),
    "DestinationHostname" VARCHAR(255),
    "DestinationPort" VARCHAR(255),
    PRIMARY KEY ("ConnectionId")
);

CREATE TABLE  "app_example"
(
    id SERIAL,
    name VARCHAR(255),
    url VARCHAR(255),
    source VARCHAR(255),
    category VARCHAR(255)
);

CREATE TABLE  "PSEvents"
(
    id SERIAL,
    "UtcTime" TIMESTAMPTZ,
    application VARCHAR(8000),
    param VARCHAR(8000),
    computer_name VARCHAR(200),
    event_id VARCHAR(50)
);

INSERT INTO "app_example" (name, url, source, category) VALUES
    ('DE_sysmon-3-rdp-tun','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Command%20and%20Control/DE_sysmon-3-rdp-tun.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Command_and_Control'),
    ('discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon17_18_kekeo_tsssp_default_np','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon17_18_kekeo_tsssp_default_np.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_11_lsass_memdump','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_11_lsass_memdump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('tunna_iis_rdp_smb_tunneling_sysmon_3','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Command%20and%20Control/tunna_iis_rdp_smb_tunneling_sysmon_3.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Command_and_Control'),
    ('discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_1_memdump_comsvcs_minidump','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_1_memdump_comsvcs_minidump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_13_keylogger_directx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_13_keylogger_directx.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('Mimikatz_hosted_Github','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('DE_Powershell_CLM_Disabled_Sysmon_12','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('DE_UAC_Disabled_Sysmon_12_13','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/DE_UAC_Disabled_Sysmon_12_13.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('DSE_bypass_BYOV_TDL_dummydriver_sysmon_6_7_13','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/DSE_bypass_BYOV_TDL_dummydriver_sysmon_6_7_13.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('Sysmon%207%20%20Update%20Session%20Orchestrator%20Dll%20Hijack','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/Sysmon%207%20%20Update%20Session%20Orchestrator%20Dll%20Hijack.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('Sysmon%207%20dllhijack_cdpsshims_CDPSvc','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/Sysmon%207%20dllhijack_cdpsshims_CDPSvc.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('de_PsScriptBlockLogging_disabled_sysmon12_13','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/de_PsScriptBlockLogging_disabled_sysmon12_13.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('de_portforward_netsh_rdp_sysmon_13_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/de_portforward_netsh_rdp_sysmon_13_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('de_powershell_execpolicy_changed_sysmon_13','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/de_powershell_execpolicy_changed_sysmon_13.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('de_sysmon_13_VBA_Security_AccessVBOM','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/de_sysmon_13_VBA_Security_AccessVBOM.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('de_unmanagedpowershell_psinject_sysmon_7_8_10','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('meterpreter_migrate_to_explorer_sysmon_8','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/meterpreter_migrate_to_explorer_sysmon_8.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('process_suspend_sysmon_10_ga_800','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/process_suspend_sysmon_10_ga_800.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('sysmon_10_1_ppid_spoofing','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/sysmon_10_1_ppid_spoofing.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('sysmon_13_rdp_settings_tampering','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/sysmon_13_rdp_settings_tampering.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('sysmon_2_11_evasion_timestomp_MACE','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/sysmon_2_11_evasion_timestomp_MACE.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('discovery_UEFI_Settings_rweverything_sysmon_6','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_UEFI_Settings_rweverything_sysmon_6.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('discovery_enum_shares_target_sysmon_3_18','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_enum_shares_target_sysmon_3_18.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('discovery_meterpreter_ps_cmd_process_listing_sysmon_10','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('discovery_sysmon_3_Invoke_UserHunter_SourceMachine','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_sysmon_3_Invoke_UserHunter_SourceMachine.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('de_unmanagedpowershell_psinject_sysmon_7_8_10','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution')
;