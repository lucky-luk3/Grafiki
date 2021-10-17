import json
import pathlib

import logging

from .src.database import sql_initialitation, sql_connection
from .elastic import es_get_all

# Basic configuration for logging
logging.basicConfig(format='%(name)s | %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def insert_process(cursor, event):
    if "ExecutionProcessID" in event["event_data"]:
        event["event_data"]["ProcessId"] = event["event_data"]["ExecutionProcessID"]
        
    query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                        "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                            (event["event_data"]["Image"]).lower(),
                            event["event_data"]["ProcessId"],
                            event["event_data"]["Image"])
    cursor.execute(query_process)


def beat_parser_simple(path, es=False, date_from="", date_to="", filters="", options=""):
    import time
    cursor = sql_connection()
    sql_initialitation(cursor)
    connections_key = 100000000
    thread_key = 0
    files_inserted = []
    full_process_inserted = []
    pipes_inserted = []
    threads_inserted = []
    start = time.time()
    if not es:
        f = open(path,)

    else:
        if date_to and date_from:
            if filters:
                f = es_get_all(date_from, date_to, filters, options)
            else:
                f = es_get_all(date_from, date_to, filters, options)
        else:
            f = es_get_all()
    for line in f:
        if not es:
            event = json.loads(line)
        else:
            event = line
        if "SourceName" in event:
            event["log_name"] = event["SourceName"]
            if "Sysmon" in event["SourceName"]:
                #event =  {k.lower(): v for k, v in event.items()}
                event["computer_name"] = event["Hostname"]
                event["event_id"] = event["EventID"]         
                if "event_data" not in event:
                    event["event_data"] = event
        if "log_name" in event or "SourceName" in event:
            if "Sysmon" in event["log_name"] or "Sysmon" in event["SourceName"]:
                # Process Creation
                if event["event_id"] == 1:
                    try:
                        if event["event_data"]["ProcessGuid"] not in full_process_inserted:
                            if "ExecutionProcessID" in event["event_data"]:
                                event["event_data"]["ProcessId"] = event["event_data"]["ExecutionProcessID"]

                            query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image","IntegrityLevel",' \
                                            '"TerminalSessionId", "User")' \
                                            " VALUES ('{}','{}','{}','{}','{}', '{}')" \
                                            ' ON CONFLICT ("ProcessGuid") DO UPDATE SET "IntegrityLevel" = ' \
                                            'EXCLUDED."IntegrityLevel", "TerminalSessionId"' \
                                            ' = EXCLUDED."TerminalSessionId", "User" =  EXCLUDED."User";'.format(
                                                (event["event_data"]["Image"]).lower(),
                                                event["event_data"]["ProcessId"],
                                                event["event_data"]["Image"],
                                                event["event_data"]["IntegrityLevel"],
                                                event["event_data"]["TerminalSessionId"],
                                                event["event_data"]["User"])
                            cursor.execute(query_process)
                            full_process_inserted.append(event["event_data"]["ProcessGuid"])
                    except Exception as e:
                        logger.error("Error query_process 1: " + str(e) + " Event: " + str(event))

                    try:
                        query_pprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                         "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                                            (event["event_data"]["ParentImage"]).lower(),
                                            event["event_data"]["ParentProcessId"],
                                            event["event_data"]["ParentImage"])
                        cursor.execute(query_pprocess)

                    except Exception as e:
                        logger.error("Error query_pprocess_exist 1: " + str(e) + " Event: " + str(query_pprocess))

                    try:
                        if event["event_data"]["CommandLine"]:
                            event["event_data"]["CommandLine"] = str(
                                event["event_data"]["CommandLine"]).replace("'", "\"")

                        if event["event_data"]["CurrentDirectory"]:
                            event["event_data"]["CurrentDirectory"] = str(
                                event["event_data"]["CurrentDirectory"]).replace("'", "\"")

                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","LogonGuid","DestinationId",' \
                                       '"ExtraInfo","ExtraInfo2")' \
                                       " VALUES ('{}','{}','{}','{}','{}','{}','{}');".format(
                                        event["event_data"]["UtcTime"], "CreateProcess",
                                        (event["event_data"]["ParentImage"]).lower(),
                                        event["event_data"]["LogonGuid"],
                                        (event["event_data"]["Image"]).lower(),
                                        event["event_data"]["CommandLine"],
                                        event["event_data"]["CurrentDirectory"])
                        cursor.execute(query_action)
                    except Exception as e:
                        logger.error("Error query_action 1: " + str(e) + " Event: " + str(query_action))

                    try:
                        query_user = 'INSERT INTO public."Users" ("LogonGuid","Name","LogonId","TerminalSessionId") VALUES' \
                                     " ('{}','{}','{}',{}) ON CONFLICT DO NOTHING;".format(
                                        event["event_data"]["LogonGuid"],
                                        event["event_data"]["User"],
                                        event["event_data"]["LogonId"],
                                        event["event_data"]["TerminalSessionId"])
                        cursor.execute(query_user)
                    except Exception as e:
                        print("Error 1: " + str(e) + " Event: " + str(query_user))

                # Network connection
                if event["event_id"] == 3:
                    try:
                        if "DestinationHostname" not in event["event_data"]:
                            event["event_data"]["DestinationHostname"] = ""
                        if "SourceHostname" not in event["event_data"]:
                            event["event_data"]["SourceHostname"] = ""

                        connections_key = str(event["event_data"]["SourceIp"]) + str(
                            event["event_data"]["DestinationIp"])
                        query_connection = 'INSERT INTO public."Connections" ("ConnectionId","Protocol","SourceIp","SourceHostname",' \
                                           '"SourcePort","DestinationIsIpv6","DestinationIp","DestinationHostname","DestinationPort") ' \
                                           "VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}') ON CONFLICT DO NOTHING;".format(
                                            connections_key, event["event_data"]["Protocol"],
                                            event["event_data"]["SourceIp"],
                                            event["event_data"]["SourceHostname"],
                                            event["event_data"]["SourcePort"],
                                            event["event_data"]["DestinationIsIpv6"],
                                            event["event_data"]["DestinationIp"],
                                            event["event_data"]["DestinationHostname"],
                                            event["event_data"]["DestinationPort"])
                        cursor.execute(query_connection)
                    except Exception as e:
                        print("Error query_connection 3: " + str(e) + " Event: " + str(query_connection))

                    try:
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","LogonGuid","DestinationId",' \
                                       '"ExtraInfo")' \
                                       " VALUES ('{}','{}','{}','{}','{}','{}');".format(
                                        event["event_data"]["UtcTime"], "CreateConnection",
                                        (event["event_data"]["Image"]).lower(),
                                        event["event_data"]["User"],
                                        connections_key,
                                        event["event_data"]["Initiated"])
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 3: " + str(e) + " Event: " + str(query_action))

                    try:
                        insert_process(cursor, event)
                    except Exception as e:
                        print("Error query_pprocess_exist 3: " + str(e) + " Event: " + str(event))

                # Process Terminated
                if event["event_id"] == 5:
                    try:  # Destination Process
                        query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                        "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                            (event["event_data"]["Image"]).lower(),
                            event["event_data"]["ProcessId"],
                            event["event_data"]["Image"])
                        cursor.execute(query_process)

                    except Exception as e:
                        print("Error query_sprocess 5: " + str(e) + " Event: " + str(query_process))

                    try:  # Action
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                       " VALUES ('{}','{}','{}','{}');".format(
                            event["event_data"]["UtcTime"],
                            "ProcessTerminated",
                            (event["event_data"]["Image"]).lower(),
                            (event["event_data"]["Image"]).lower())
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 5: " + str(e) + " Event: " + str(query_action))

                #  Kernel driver loaded
                if event["event_id"] == 6:
                    logger.info("ToDo")

                #  Image loaded
                if event["event_id"] == 7:
                    try:  # Process
                        insert_process(cursor, event)
                    except Exception as e:
                        print("Error query_sprocess 7: " + str(e) + " Event: " + str(query_sprocess))

                    try:  # File
                        if "Description" not in event["event_data"]:
                            event["event_data"]["Description"] = ""
                        if "Signature" not in event["event_data"]:
                            event["event_data"]["Signature"] = ""
                        if "OriginalFileName" not in event["event_data"]:
                            event["event_data"]["OriginalFileName"] = ""

                        query_file = 'INSERT INTO public."Files" ("Filename","FileVersion","Description","Product","Company","OriginalFileName","Hashes","Signed","Signature","SignatureStatus") ' \
                                     " VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}') ON CONFLICT" \
                                     ' ("Filename") DO UPDATE SET' \
                                     ' "FileVersion" = EXCLUDED."FileVersion", "Description" = EXCLUDED."Description",' \
                                     ' "Product" =  EXCLUDED."Product", "Company" = EXCLUDED."Company",' \
                                     '"OriginalFileName" = EXCLUDED."OriginalFileName","Hashes" = EXCLUDED."Hashes"' \
                                     ',"Signed" = EXCLUDED."Signed","Signature" = EXCLUDED."Signature",' \
                                     '"SignatureStatus" = EXCLUDED."SignatureStatus";'.format(
                            "f:" + str(event["event_data"]["ImageLoaded"]).lower(),
                            event["event_data"]["FileVersion"],
                            event["event_data"]["Description"],
                            event["event_data"]["Product"],
                            event["event_data"]["Company"],
                            event["event_data"]["OriginalFileName"],
                            event["event_data"]["Hashes"],
                            event["event_data"]["Signed"],
                            event["event_data"]["Signature"],
                            event["event_data"]["SignatureStatus"])
                        cursor.execute(query_file)
                    except Exception as e:
                        print("Error query_file 7: " + str(e) + " Event: " + str(query_file))

                    try:  # Action
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                       " VALUES ('{}','{}','{}','{}');".format(
                            event["event_data"]["UtcTime"],
                            "LoadImage",
                            "f:" + str(event["event_data"]["ImageLoaded"]).lower(),
                            (event["event_data"]["Image"]).lower())
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 7: " + str(e) + " Event: " + str(query_action))

                # Create Remote Thread
                if event["event_id"] == 8:
                    try:  # Source Process
                        query_sprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image")' \
                                         " VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;" \
                            .format((event["event_data"]["SourceImage"]).lower(),
                                    event["event_data"]["SourceProcessId"],
                                    (event["event_data"]["SourceImage"]).lower())
                        cursor.execute(query_sprocess)

                    except Exception as e:
                        print("Error query_sprocess 8: " + str(e) + " Event: " + str(query_sprocess))

                    try:  # Target Process
                        query_tprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                         "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                            (event["event_data"]["TargetImage"]).lower(),
                            event["event_data"]["TargetProcessId"],
                            (event["event_data"]["TargetImage"]).lower())
                        cursor.execute(query_tprocess)

                    except Exception as e:
                        print("Error query_tprocess 8: " + str(e) + " Event: " + str(query_tprocess))

                    try:  # Thread
                        thread_key = str(event["event_data"]["TargetProcessGuid"]) + ":" + str(
                            event["event_data"]["NewThreadId"])
                        query_thread = 'INSERT INTO public."Threads" ("ThreadId","ThreadNId","ProcessGuid","StartAddress",' \
                                       '"StartModule", "StartFunction")' \
                                       " VALUES ('{}','{}','{}','{}','{}','{}') ON CONFLICT " \
                                       '("ThreadId") DO UPDATE SET "StartAddress" = ' \
                                       'EXCLUDED."StartAddress", "StartModule"' \
                                       ' = EXCLUDED."StartModule", "StartFunction"' \
                                       ' = EXCLUDED."StartFunction";'.format(
                            thread_key,
                            event["event_data"]["NewThreadId"],
                            (event["event_data"]["TargetImage"]).lower(),
                            event["event_data"]["StartAddress"],
                            event["event_data"]["StartModule"],
                            event["event_data"]["StartFunction"])
                        cursor.execute(query_thread)

                    except Exception as e:
                        print("Error query_thread 8: " + str(e) + " Event: " + str(query_thread))

                    try:  # Action
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                       " VALUES ('{}','{}','{}','{}');".format(
                            event["event_data"]["UtcTime"],
                            "CreateRemoteThread",
                            (event["event_data"]["SourceImage"]).lower(),
                            thread_key)
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 8: " + str(e) + " Event: " + str(query_action))

                # Raw access read
                if event["event_id"] == 9:
                    logger.info("ToDo")

                #  Process Access
                if event["event_id"] == 10:
                    try:
                        query_pprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                         "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                            (event["event_data"]["SourceImage"]).lower(),
                            event["event_data"]["SourceProcessId"],
                            (event["event_data"]["SourceImage"]).lower())
                        cursor.execute(query_pprocess)
                    except Exception as e:
                        logger.error("Error query_Pprocess 10: " + str(e) + " Event: " + str(query_pprocess))

                    try:
                        query_tprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                         "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                            (event["event_data"]["TargetImage"]).lower(),
                            event["event_data"]["TargetProcessId"],
                            (event["event_data"]["TargetImage"]).lower())
                        cursor.execute(query_tprocess)
                    except Exception as e:
                        logger.error("Error query_tprocess 10: " + str(e) + " Event: " + str(query_tprocess))
                    """
                    try:  # File - Actions
                        dlls = str(event["event_data"]["CallTrace"]).split("|")
                        for dll in dlls:
                            path = dll.split("+")
                            if (path[0]).lower() not in (event["event_data"]["SourceImage"]).lower():
                                query_file = 'INSERT INTO public."Files" ("Filename") ' \
                                               "VALUES ('{}') ON CONFLICT DO NOTHING;".format(
                                                "f:" + str(path[0]).lower())
                                cursor.execute(query_file)

                                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                               " VALUES ('{}','{}','{}','{}');".format(
                                    event["event_data"]["UtcTime"],
                                    "LoadImage",
                                    "f:" + str(path[0]).lower(),
                                    (event["event_data"]["SourceImage"]).lower())
                                cursor.execute(query_action)

                    except Exception as e:
                        print("Error query_file 10: " + str(e) + " Event: " + str(query_file))



                    try:  # Thread
                        thread = str(event["event_data"]["SourceThreadId"]) + str(event["event_data"]["SourceProcessGUID"])
                        if thread not in threads_inserted:
                            thread_key += 1
                            query_thread = 'INSERT INTO public."Threads" ("ThreadId","ThreadNId","ProcessGuid")' \
                                           " VALUES ({},{},'{}') ON CONFLICT DO NOTHING;".format(
                                            thread_key,
                                            event["event_data"]["SourceThreadId"],
                                            event["event_data"]["SourceProcessGUID"])
                            cursor.execute(query_thread)
                            threads_inserted.append(thread)
                        else:
                            logger.info("Thread duplicate")
                    except Exception as e:
                        print("Error query_thread 10: " + str(e) + " Event: " + str(query_thread))
                    """
                    try:
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId",' \
                                       '"ExtraInfo","ExtraInfo2")' \
                                       " VALUES ('{}','{}','{}','{}','{}','{}');".format(
                            event["event_data"]["UtcTime"], "ProcessAccess",
                            (event["event_data"]["SourceImage"]).lower(),
                            (event["event_data"]["TargetImage"]).lower(),
                            event["event_data"]["GrantedAccess"],
                            event["event_data"]["CallTrace"])
                        cursor.execute(query_action)
                    except Exception as e:
                        logger.error("Error query_action 10: " + str(e) + " Event: " + str(query_action))

                #  File create
                if event["event_id"] == 11:  # Create File

                    try:  # Process
                        insert_process(cursor, event)
                    except Exception as e:
                        print("Error query_sprocess 11: " + str(e) + " Event: " + str(event["Event"]))

                    try:  # File
                        query_file = 'INSERT INTO public."Files" ("Filename","CreationUtcTime") ' \
                                     "VALUES ('{}','{}') ON CONFLICT DO NOTHING;".format(
                            "f:" + str(event["event_data"]["TargetFilename"]).lower(),
                            event["event_data"]["CreationUtcTime"])
                        cursor.execute(query_file)
                    except Exception as e:
                        print("Error query_file 11: " + str(e) + " Event: " + str(query_file))

                    try:  # Action
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                       " VALUES ('{}','{}','{}','{}');".format(
                            event["event_data"]["UtcTime"],
                            "CreateFile",
                            (event["event_data"]["Image"]).lower(),
                            "f:" + str(event["event_data"]["TargetFilename"]).lower())
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 11: " + str(e) + " Event: " + str(query_action))

                # Registry Key Operation
                if event["event_id"] == 12 or event["event_id"] == 13 \
                        or event["event_id"] == 14:
                    
                    if "EventType" not in event["event_data"]:
                        if event["event_id"] == 12 or event["event_id"] == 13:
                            event["event_data"]["EventType"] = "AddedOrDeleted"
                        elif event["event_id"] == 14:
                            event["event_data"]["EventType"] = "Renamed"

                    if event["event_data"]["TargetObject"]:
                        event["event_data"]["TargetObject"] = str(
                            event["event_data"]["TargetObject"]).replace("'", "\"")

                    try:  # Process
                        insert_process(cursor, event)
                    except Exception as e:
                        print("Error query_process 12-13-14: " + str(e) + " Event: " + str(event["Event"]))

                    try:  # RegistryKey
                        if event["event_id"] == 13:
                            if event["event_data"]["Details"]:
                                event["event_data"]["Details"] = str(
                                    event["event_data"]["Details"]).replace("'", "\"")

                            query_key = 'INSERT INTO public."RegistryKeys" ("Key","Details") ' \
                                        "VALUES ('{}','{}') ON CONFLICT DO NOTHING;".format(
                                event["event_data"]["TargetObject"],
                                event["event_data"]["Details"])
                        else:
                            query_key = 'INSERT INTO public."RegistryKeys" ("Key") ' \
                                        "VALUES ('{}') ON CONFLICT DO NOTHING;".format(
                                event["event_data"]["TargetObject"])
                        cursor.execute(query_key)
                    except Exception as e:
                        print("Error query_key 12-13-14: " + str(e) + " Event: " + str(query_key))

                    try:  # Action
                        if "SetValue" in event["event_data"]["EventType"]:
                            query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId","ExtraInfo")' \
                                           " VALUES ('{}','{}','{}','{}','{}');".format(
                                event["event_data"]["UtcTime"],
                                "RegistryKey-" + event["event_data"]["EventType"],
                                (event["event_data"]["Image"]).lower(),
                                event["event_data"]["TargetObject"],
                                event["event_data"]["Details"])
                        else:
                            query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                           " VALUES ('{}','{}','{}','{}');".format(
                                event["event_data"]["UtcTime"],
                                "RegistryKey-" + event["event_data"]["EventType"],
                                (event["event_data"]["Image"]).lower(),
                                event["event_data"]["TargetObject"])
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 12-13-14: " + str(e) + " Event: " + str(query_action))

                #  File create stream hash
                if event["event_id"] == 15:
                    logger.info("ToDo")

                #  File create stream hash
                if event["event_id"] == 15:
                    logger.info("ToDo")

                # Pipe event
                if event["event_id"] == 17 or event["event_id"] == 18:
                    if event["event_id"] == 17 and "EventType" not in event["event_data"]:
                        event["event_data"]["EventType"] = "CreatePipe"
                    elif event["event_id"] == 18 and "EventType" not in event["event_data"]:
                        event["event_data"]["EventType"] = "ConnectPipe"
                    try:
                        insert_process(cursor, event)
                    except Exception as e:
                        print("Error insert_process 17-18: " + str(e) + " Event: " + str(event["Event"]))

                    try:  # Pipe
                        if event["event_data"]["PipeName"] not in pipes_inserted:
                            query_pipe = 'INSERT INTO public."Pipes" ("PipeName") ' \
                                         "VALUES ('{}');".format(
                                event["event_data"]["PipeName"])
                            cursor.execute(query_pipe)
                            pipes_inserted.append(event["event_data"]["PipeName"])
                    except Exception as e:
                        print("Error query_file 17-18: " + str(e) + " Event: " + str(query_pipe))

                    try:  # Action
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                       " VALUES ('{}','{}','{}','{}');".format(
                            event["event_data"]["UtcTime"],
                            event["event_data"]["EventType"],
                            (event["event_data"]["Image"]).lower(),
                            event["event_data"]["PipeName"])
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 17-18: " + str(e) + " Event: " + str(query_action))

                # WMI event
                if event["event_id"] == 19 or event["event_id"] == 20 \
                        or event["event_id"] == 21:
                    logger.info("ToDo")

                #  DNS
                if event["event_id"] == 22:
                    try:
                        insert_process(cursor, event)
                    except Exception as e:
                        print("Error insert_process 22: " + str(e) + " Event: " + str(event["Event"]))

                    try:  # Query
                        query_dnsquery = 'INSERT INTO public."DNSQuery" ("QueryName") ' \
                                         "VALUES ('{}') ON CONFLICT DO NOTHING;".format(
                            event["event_data"]["QueryName"])
                        cursor.execute(query_dnsquery)
                    except Exception as e:
                        print("Error query_file 22: " + str(e) + " Event: " + str(query_dnsquery))

                    try:  # Resolution
                        query_dnsresolution = 'INSERT INTO public."DNSResolution" ("UtcTime","QueryName","QueryStatus","QueryResults") ' \
                                              "VALUES ('{}','{}','{}','{}') ON CONFLICT DO NOTHING;".format(
                            event["event_data"]["UtcTime"],
                            event["event_data"]["QueryName"],
                            event["event_data"]["QueryStatus"],
                            event["event_data"]["QueryResults"])
                        cursor.execute(query_dnsresolution)
                    except Exception as e:
                        print("Error query_file 22: " + str(e) + " Event: " + str(query_dnsresolution))

                    try:  # Action
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                       " VALUES ('{}','{}','{}','{}') ;".format(
                            event["event_data"]["UtcTime"],
                            "DnsRequest",
                            (event["event_data"]["Image"]).lower(),
                            event["event_data"]["QueryName"])
                        cursor.execute(query_action)
                    except Exception as e:
                        print("Error query_action 22: " + str(e) + " Event: " + str(query_action))
            """
            elif "Microsoft-Windows-PowerShell/Operational" in event["log_name"]:
                # print("entra en power beat")
                try:
                    if event["event_data"]["application"]:
                        event["event_data"]["application"] = str(
                            event["event_data"]["application"]).replace("'", "\"")
                        event["event_data"]["application"] = str(
                            event["event_data"]["application"]).replace('"', "\"")
                    if event["event_data"]["param"]:
                        event["event_data"]["param"] = str(
                            event["event_data"]["param"]).replace("'", "\"")
                        event["event_data"]["param"] = str(
                            event["event_data"]["param"]).replace('"', "\"")

                    # root | Error query_psevent: 'application' query_psevent:

                    query_psevent = 'INSERT INTO public."PSEvents" ("event_id","UtcTime","application","param", "computer_name")' \
                                    " VALUES ('{}','{}','{}','{}','{}') ON CONFLICT DO NOTHING;".format(
                        event["event_id"],
                        event["event_data"]["log_ingest_timestamp"],
                        event["event_data"]["application"],
                        event["event_data"]["param"],
                        event["computer_name"])
                    cursor.execute(query_psevent)
                except Exception as e:
                    logger.error("Error query_psevent: " + str(e) + " query_psevent: " + str(event))
        """
        else:
            print("Invalid format")
            cursor.close()
            return False


    cursor.close()
    end = time.time()
    print("Time to process file %s seconds ---" % (end - start))
    return True
