DROP TABLE IF EXISTS 'Processes' ;
DROP TABLE IF EXISTS 'Users' ;
DROP TABLE IF EXISTS 'Actions' ;
DROP TABLE IF EXISTS 'Threads' ;
DROP TABLE IF EXISTS 'Files' ;
DROP TABLE IF EXISTS 'Connections' ;
DROP TABLE IF EXISTS 'RegistryKeys' ;
DROP TABLE IF EXISTS 'Pipes' ;
DROP TABLE IF EXISTS 'WmiFilters' ;
DROP TABLE IF EXISTS 'WmiConsumers' ;
DROP TABLE IF EXISTS 'DNSQuerys' ;
DROP TABLE IF EXISTS 'DNSResolutions' ;

CREATE TABLE IF NOT EXISTS DNSResolution
(
    'UtcTime' DATETIME2(3),
	'QueryName' VARCHAR(255),
	'QueryStatus' VARCHAR(255),
	'QueryResults' VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS DNSQuery
(
	'QueryName' VARCHAR(255) PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS Pipes
(
	'PipeName' VARCHAR(255) PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS Files
(
	'Filename' VARCHAR(255),
	'OriginalFileName' VARCHAR(255),
    'CreationUtcTime' DATETIME2(3),
	'Description' VARCHAR(255),
	'Company' VARCHAR(255),
	'Hashes' VARCHAR(255),
	'Signed' VARCHAR(255),
	'Signature' VARCHAR(255),
	'SignatureStatus' VARCHAR(255),
	'Product' VARCHAR(255),
	'FileVersion' VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS RegistryKeys
(
	'Key' VARCHAR(510) PRIMARY KEY,
    'Details' VARCHAR(510)
);

CREATE TABLE IF NOT EXISTS Processes
(
    'ProcessGuid' VARCHAR(255) PRIMARY KEY,
    'ProcessId' INT,
    'Image' VARCHAR(255),
    'IntegrityLevel' VARCHAR(255),
    'TerminalSessionId' INT
);

CREATE TABLE IF NOT EXISTS Users
(
    'LogonGuid' VARCHAR(255) PRIMARY KEY,
    'Name' VARCHAR(255),
    'LogonId' VARCHAR(255),
    'TerminalSessionId' INT,
    'UserID' VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS Actions
(
    'UtcTime' DATETIME2(3),
    'ActionType' VARCHAR(255),
    'ProcessGuid' VARCHAR(255),
    'LogonGuid' VARCHAR(255),
    'DestinationId' VARCHAR(255),
    'ExtraInfo' VARCHAR(255),
    'ExtraInfo2' VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS Threads
(
    'ThreadId' VARCHAR(255),
    'ThreadNId' INT,
    'StartAddress' VARCHAR(255),
    'StartModule' VARCHAR(255),
    'StartFunction' VARCHAR(255),
    'ProcessGuid' VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS Connections
(
    'ConnectionId' INT,
    'Protocol' VARCHAR(255),
    'SourceIp' VARCHAR(255),
    'SourceHostname' VARCHAR(255),
    'SourcePort' VARCHAR(255),
    'DestinationIsIpv6' VARCHAR(255),
    'DestinationIp' VARCHAR(255),
    'DestinationHostname' VARCHAR(255),
    'DestinationPort' VARCHAR(255),
    PRIMARY KEY (ConnectionId)
);