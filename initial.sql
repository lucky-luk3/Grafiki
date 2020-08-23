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
    "ThreadId" VARCHAR(510) PRIMARY KEY,
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

CREATE TABLE  "app_file"
(
    id SERIAL,
    name VARCHAR(255),
    evtx VARCHAR(255),
    processed VARCHAR(255),
    test VARCHAR(255)
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
    ('tunna_iis_rdp_smb_tunneling_sysmon_3','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Command%20and%20Control/tunna_iis_rdp_smb_tunneling_sysmon_3.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Command_and_Control'),
    ('discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon17_18_kekeo_tsssp_default_np','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon17_18_kekeo_tsssp_default_np.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_11_lsass_memdump','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_11_lsass_memdump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_1_memdump_comsvcs_minidump','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_1_memdump_comsvcs_minidump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('sysmon_13_keylogger_directx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_13_keylogger_directx.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    ('Mimikatz_hosted_Github','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access'),
    --('covenant_dcsync_all','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/covenant_dcsync_all.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('covenant_lsacache','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/covenant_lsacache.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('covenant_lsasecrets','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/covenant_lsasecrets.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('covenant_mimikatz_logonpasswords','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/covenant_mimikatz_logonpasswords.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_dcsync','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_dcsync.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('empire_extended_netntlm_downgrade','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_extended_netntlm_downgrade.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_mimikatz_export_master_key','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_mimikatz_export_master_key.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_mimikatz_extract_tickets','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_mimikatz_extract_tickets.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_mimikatz_logonpasswords','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_mimikatz_logonpasswords.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_mimikatz_lsadump_sam','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_mimikatz_lsadump_sam.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_mimikatz_opth','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_mimikatz_opth.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_powerdump','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_powerdump.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    ('empire_reg_dump_sam','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_reg_dump_sam.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('empire_rubeus_asktgt_ptt','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_rubeus_asktgt_ptt.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('empire_rubeus_asktgt_ptt_createnetonly','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/empire_rubeus_asktgt_ptt_createnetonly.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('interactive_taskmngr_lsass_dump','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/interactive_taskmngr_lsass_dump.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
    --('remoteinteractive_taskmngr_lsass_dump','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/credential_access/remoteinteractive_taskmngr_lsass_dump.tar.gz','https://github.com/hunters-forge/mordor','Credential_Access'),
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
    --('meterpreter_migrate_to_explorer_sysmon_8','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/meterpreter_migrate_to_explorer_sysmon_8.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'), #problema en evento8 thread
    ('process_suspend_sysmon_10_ga_800','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/process_suspend_sysmon_10_ga_800.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('sysmon_10_1_ppid_spoofing','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/sysmon_10_1_ppid_spoofing.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('sysmon_13_rdp_settings_tampering','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/sysmon_13_rdp_settings_tampering.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    ('sysmon_2_11_evasion_timestomp_MACE','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/sysmon_2_11_evasion_timestomp_MACE.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Defense_Evasion'),
    --('covenant_installutil','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/covenant_installutil.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    --('covenant_msbuild_grunt','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/covenant_msbuild_grunt.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    ('empire_dcsync_acl','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/empire_dcsync_acl.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    ('empire_dll_injection','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/empire_dll_injection.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    ('empire_enable_rdp','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/empire_enable_rdp.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    ('empire_invoke_msbuild','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/empire_invoke_msbuild.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    ('empire_psinject','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/empire_psinject.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    ('empire_wdigest_downgrade','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/defense_evasion/empire_wdigest_downgrade.tar.gz','https://github.com/hunters-forge/mordor','Defense_Evasion'),
    --('discovery_UEFI_Settings_rweverything_sysmon_6','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_UEFI_Settings_rweverything_sysmon_6.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('discovery_enum_shares_target_sysmon_3_18','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_enum_shares_target_sysmon_3_18.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    --('discovery_meterpreter_ps_cmd_process_listing_sysmon_10','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'), #en parse problema con thread
    ('discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('discovery_sysmon_3_Invoke_UserHunter_SourceMachine','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Discovery/discovery_sysmon_3_Invoke_UserHunter_SourceMachine.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Discovery'),
    ('empire_find_local_admin','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/discovery/empire_find_local_admin.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_get_session_local','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/discovery/empire_get_session_local.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_net_domain_admins','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/discovery/empire_net_domain_admins.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_net_local_admins','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/discovery/empire_net_local_admins.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_net_user','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/discovery/empire_net_user.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_net_user_domain','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/discovery/empire_net_user_domain.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_net_user_domain_specific','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/discovery/empire_net_user_domain_specific.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('Exec_sysmon_meterpreter_reversetcp_msipackage','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('Exec_via_cpl_Application_Experience_EventID_17_ControlPanelApplet','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/Exec_via_cpl_Application_Experience_EventID_17_ControlPanelApplet.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('Sysmon_Exec_CompiledHTML','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/Sysmon_Exec_CompiledHTML.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('Sysmon_meterpreter_ReflectivePEInjection_to_notepad_','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_driveby_cve-2018-15982_sysmon_1_10','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_driveby_cve-2018-15982_sysmon_1_10.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_msxsl_xsl_sysmon_1_7','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_msxsl_xsl_sysmon_1_7.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_7_jscript9_defense_evasion','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_7_jscript9_defense_evasion.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_ftp','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_ftp.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_lolbin_pcalua','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_lolbin_pcalua.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_lolbin_renamed_regsvr32_scrobj','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_1_rundll32_pcwutl_LaunchApplication','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_sysmon_lobin_regsvr32_sct','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_sysmon_lobin_regsvr32_sct.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('exec_wmic_xsl_internet_sysmon_3_1_11','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/exec_wmic_xsl_internet_sysmon_3_1_11.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('revshell_cmd_svchost_sysmon_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/revshell_cmd_svchost_sysmon_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('sysmon_1_11_rundll32_cpl_ostap','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/sysmon_1_11_rundll32_cpl_ostap.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('sysmon_exec_from_vss_persistence','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/sysmon_exec_from_vss_persistence.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('sysmon_lolbas_rundll32_zipfldr_routethecall_shell','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/sysmon_lolbas_rundll32_zipfldr_routethecall_shell.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('sysmon_lolbin_bohops_vshadow_exec','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/sysmon_lolbin_bohops_vshadow_exec.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('sysmon_mshta_sharpshooter_stageless_meterpreter','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('sysmon_vbs_sharpshooter_stageless_meterpreter','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/sysmon_vbs_sharpshooter_stageless_meterpreter.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Execution'),
    ('covenant_powerhell_system_reflection_assembly_load','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/execution/covenant_powerhell_system_reflection_assembly_load.tar.gz','https://github.com/hunters-forge/mordor','Execution'),
    ('empire_invoke_psexec','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/execution/empire_invoke_psexec.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_invoke_psremoting','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/execution/empire_invoke_psremoting.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_invoke_wmi','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/execution/empire_invoke_wmi.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_invoke_wmi_debugger','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/execution/empire_invoke_wmi_debugger.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_launcher_vbs','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/execution/empire_launcher_vbs.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('empire_wmic_add_user','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/execution/empire_wmic_add_user.tar.gz','https://github.com/hunters-forge/mordor','Discovery'),
    ('LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_PowershellRemoting_sysmon_1_wsmprovhost','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_impacket_docmexec_mmc_sysmon_01','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_impacket_docmexec_mmc_sysmon_01.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_sysmon_psexec_smb_meterpreter','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_sysmon_psexec_smb_meterpreter.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_tsclient_startup_folder','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_tsclient_startup_folder.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_typical_IIS_webshell_sysmon_1_10_traces','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_typical_IIS_webshell_sysmon_1_10_traces.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_winrm_exec_sysmon_1_winrshost','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_winrm_exec_sysmon_1_winrshost.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('LM_wmiexec_impacket_sysmon_whoami','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/LM_wmiexec_impacket_sysmon_whoami.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('lm_sysmon_18_remshell_over_namedpipe','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/lm_sysmon_18_remshell_over_namedpipe.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('powercat_revShell_sysmon_1_3','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/powercat_revShell_sysmon_1_3.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('sharprdp_sysmon_7_mstscax','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/sharprdp_sysmon_7_mstscax.dll.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    ('sysmon_1_exec_via_sql_xpcmdshell','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/sysmon_1_exec_via_sql_xpcmdshell.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Lateral_Movement'),
    --('covenant_psremoting_grunt','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/lateral_movement/covenant_psremoting_grunt.tar.gz','https://github.com/hunters-forge/mordor','Lateral_Movement'),
    ('empire_invoke_dcom','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/lateral_movement/empire_invoke_dcom.tar.gz','https://github.com/hunters-forge/mordor','Lateral_Movement'),
    ('empire_invoke_smbexec','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/lateral_movement/empire_invoke_smbexec.tar.gz','https://github.com/hunters-forge/mordor','Lateral_Movement'),
    ('empire_scm_dll_hijack_ikeext','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/lateral_movement/empire_scm_dll_hijack_ikeext.tar.gz','https://github.com/hunters-forge/mordor','Lateral_Movement'),
    ('Persistence_Winsock_Catalog%20Change%20EventId_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/Persistence_Winsock_Catalog%20Change%20EventId_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persist_firefox_comhijack_sysmon_11_13_7_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persistence_SilentProcessExit_ImageHijack_sysmon_13_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persist_turla_outlook_backdoor_comhijack','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persist_turla_outlook_backdoor_comhijack.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persist_valid_account_guest_rid_hijack','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persist_valid_account_guest_rid_hijack.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persistence_SilentProcessExit_ImageHijack_sysmon_13_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persistence_accessibility_features_osk_sysmon1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persistence_accessibility_features_osk_sysmon1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persistence_startup_UserShellStartup_Folder_Changed_sysmon_13','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persistence_startup_UserShellStartup_Folder_Changed_sysmon_13.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('persistence_sysmon_11_13_1_shime_appfix','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('sysmon_13_1_persistence_via_winlogon_shell','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/sysmon_13_1_persistence_via_winlogon_shell.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('sysmon_1_persist_bitsjob_SetNotifyCmdLine','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('sysmon_20_21_1_CommandLineEventConsumer','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    ('wmighost_sysmon_20_21_1','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Persistence/wmighost_sysmon_20_21_1.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Persistence'),
    --('covenant_persiststartup','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/persistence/covenant_persiststartup.tar.gz','https://github.com/hunters-forge/mordor','Persistence'),
    --('covenant_persistwmi','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/persistence/covenant_persistwmi.tar.gz','https://github.com/hunters-forge/mordor','Persistence'),
    ('empire_elevated_registry','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/persistence/empire_elevated_registry.tar.gz','https://github.com/hunters-forge/mordor','Persistence'),
    ('empire_elevated_schtasks','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/persistence/empire_elevated_schtasks.tar.gz','https://github.com/hunters-forge/mordor','Persistence'),
    ('empire_elevated_wmi','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/persistence/empire_elevated_wmi.tar.gz','https://github.com/hunters-forge/mordor','Persistence'),
    ('empire_userland_registry','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/persistence/empire_userland_registry.tar.gz','https://github.com/hunters-forge/mordor','Persistence'),
    ('empire_userland_schtasks','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/persistence/empire_userland_schtasks.tar.gz','https://github.com/hunters-forge/mordor','Persistence'),
    ('PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('RogueWinRM','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/RogueWinRM.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_13_1_UACBypass_SDCLTBypass','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_13_1_UAC_Bypass_EventVwrBypass','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_22','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_22.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_23','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_23.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_30','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_30.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_32','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_32.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_33','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_33.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_34','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_34.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_36_FileCreate','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_36_FileCreate.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_37_FileCreate','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_37_FileCreate.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_38','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_38.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_39','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_39.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_41','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_41.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_43','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_43.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_45','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_45.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_53','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_53.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_54','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_54.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_UACME_56','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_UACME_56.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('Sysmon_uacme_58','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/Sysmon_uacme_58.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('UACME_61_Changepk','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/UACME_61_Changepk.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('privesc_roguepotato_sysmon_17_18','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/privesc_roguepotato_sysmon_17_18.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('privesc_seimpersonate_tosys_spoolsv_sysmon_17_18','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('privesc_unquoted_svc_sysmon_1_11','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/privesc_unquoted_svc_sysmon_1_11.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_11_1_15_WScriptBypassUAC','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_11_1_15_WScriptBypassUAC.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_11_1_7_uacbypass_cliconfg','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_11_1_7_uacbypass_cliconfg.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_11_7_1_uacbypass_windirectory_mocking','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_11_7_1_uacbypass_windirectory_mocking.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_13_1_12_11_perfmonUACBypass','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_13_1_12_11_perfmonUACBypass.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_13_1_compmgmtlauncherUACBypass','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_13_1_compmgmtlauncherUACBypass.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_1_11_exec_as_system_via_schedtask','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_1_11_exec_as_system_via_schedtask.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_1_13_11_cmstp_ini_uacbypass','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_1_13_11_cmstp_ini_uacbypass.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_1_13_UACBypass_AppPath_Control','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_1_13_UACBypass_AppPath_Control.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_1_7_11_mcx2prov_uacbypass','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_1_7_11_mcx2prov_uacbypass.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_1_7_11_migwiz','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_1_7_11_migwiz.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_1_7_11_sysprep_uacbypass','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_1_7_11_sysprep_uacbypass.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_1_7_elevate_uacbypass_sysprep','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_1_7_elevate_uacbypass_sysprep.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('sysmon_privesc_from_admin_to_system_handle_inheritance','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Privilege%20Escalation/sysmon_privesc_from_admin_to_system_handle_inheritance.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Privilege_Escalation'),
    ('empire_invoke_runas','https://github.com/hunters-forge/mordor/raw/master/datasets/small/windows/privilege_escalation/empire_invoke_runas.tar.gz','https://github.com/hunters-forge/mordor','Privilege_Escalation')
;