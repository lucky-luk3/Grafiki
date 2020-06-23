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
    ('sysmon_10_11_lsass_memdump','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/sysmon_10_11_lsass_memdump.evtx','https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES','Credential_Access')
;