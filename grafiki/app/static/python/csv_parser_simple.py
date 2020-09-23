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
    query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                        "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                            (event["Image"]).lower(),
                            event["ProcessId"],
                            event["Image"])
    cursor.execute(query_process)


def beat_parser_simple(path, es=False, date_from="", date_to="", filters="", options=""):
    import time
    cursor = sql_connection()
    sql_initialitation(cursor)
    print("Path: " + str(path))
    current_path = pathlib.Path().absolute()
    print("Current Path: " + str(current_path))
    p = str(current_path) + "/media/" + str(path)
    with open(p, newline='\n') as csvfile:
        r = csv.DictReader(csvfile, delimiter=';')
        connections_key = 100000000
        thread_key = 0
        files_inserted = []
        full_process_inserted = []
        pipes_inserted = []
        threads_inserted = []
        start = time.time()

        for event in r:   
            if event["idEvent"] == 1:
                try:
                    if event["Image"] + event["ProcessId"] not in full_process_inserted:
                        if not "TerminalSessionId" in event:
                            event["TerminalSessionId"] = 1
                        query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image","IntegrityLevel",' \
                                        '"TerminalSessionId", "User")' \
                                        " VALUES ('{}','{}','{}','{}','{}', '{}')" \
                                        ' ON CONFLICT ("ProcessGuid") DO UPDATE SET "IntegrityLevel" = ' \
                                        'EXCLUDED."IntegrityLevel", "TerminalSessionId"' \
                                        ' = EXCLUDED."TerminalSessionId", "User" =  EXCLUDED."User";'.format(
                                            (event["Image"]).lower(),
                                            event["ProcessId"],
                                            event["Image"],
                                            event["IntegrityLevel"],
                                            event["TerminalSessionId"],
                                            event["User"])
                        cursor.execute(query_process)
                        full_process_inserted.append(event["Image"] + event["ProcessId"])
                except Exception as e:
                    logger.error("Error query_process 1: " + str(e) + " Event: " + str(event))

                try:
                    query_pprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                     "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                                        (event["ParentImage"]).lower(),
                                        event["ParentProcessId"],
                                        event["ParentImage"])
                    cursor.execute(query_pprocess)

                except Exception as e:
                    logger.error("Error query_pprocess_exist 1: " + str(e) + " Event: " + str(query_pprocess))

                try:
                    if event["CommandLine"]:
                        event["CommandLine"] = str(
                            event["CommandLine"]).replace("'", "\"")

                    if event["CurrentDirectory"]:
                        event["CurrentDirectory"] = str(
                            event["CurrentDirectory"]).replace("'", "\"")

                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","LogonGuid","DestinationId",' \
                                   '"ExtraInfo","ExtraInfo2")' \
                                   " VALUES ('{}','{}','{}','{}','{}','{}','{}');".format(
                                    event["UtcTime"], "CreateProcess",
                                    (event["ParentImage"]).lower(),
                                    event["LogonGuid"],
                                    (event["Image"]).lower(),
                                    event["CommandLine"],
                                    event["CurrentDirectory"])
                    cursor.execute(query_action)
                except Exception as e:
                    logger.error("Error query_action 1: " + str(e) + " Event: " + str(query_action))

                try:
                    query_user = 'INSERT INTO public."Users" ("LogonGuid","Name","LogonId","TerminalSessionId") VALUES' \
                                 " ('{}','{}','{}',{}) ON CONFLICT DO NOTHING;".format(
                                    event["LogonGuid"],
                                    event["User"],
                                    event["LogonId"],
                                    event["TerminalSessionId"])
                    cursor.execute(query_user)
                except Exception as e:
                    print("Error 1: " + str(e) + " Event: " + str(query_user))

            # Network connection
            if event["idEvent"] == 3:
                try:
                    if "DestinationHostname" not in event:
                        event["DestinationHostname"] = ""
                    if "SourceHostname" not in event:
                        event["SourceHostname"] = ""

                    connections_key = str(event["SourceIp"]) + str(
                        event["DestinationIp"])
                    query_connection = 'INSERT INTO public."Connections" ("ConnectionId","Protocol","SourceIp","SourceHostname",' \
                                       '"SourcePort","DestinationIsIpv6","DestinationIp","DestinationHostname","DestinationPort") ' \
                                       "VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}') ON CONFLICT DO NOTHING;".format(
                                        connections_key, event["Protocol"],
                                        event["SourceIp"],
                                        event["SourceHostname"],
                                        event["SourcePort"],
                                        event["DestinationIsIpv6"],
                                        event["DestinationIp"],
                                        event["DestinationHostname"],
                                        event["DestinationPort"])
                    cursor.execute(query_connection)
                except Exception as e:
                    print("Error query_connection 3: " + str(e) + " Event: " + str(query_connection))

                try:
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","LogonGuid","DestinationId",' \
                                   '"ExtraInfo")' \
                                   " VALUES ('{}','{}','{}','{}','{}','{}');".format(
                                    event["UtcTime"], "CreateConnection",
                                    (event["Image"]).lower(),
                                    event["User"],
                                    connections_key,
                                    event["Initiated"])
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 3: " + str(e) + " Event: " + str(query_action))

                try:
                    insert_process(cursor, event)
                except Exception as e:
                    print("Error query_pprocess_exist 3: " + str(e) + " Event: " + str(event))

            # Process Terminated
            if event["idEvent"] == 5:
                try:  # Destination Process
                    query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                    "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                        (event["Image"]).lower(),
                        event["ProcessId"],
                        event["Image"])
                    cursor.execute(query_process)

                except Exception as e:
                    print("Error query_sprocess 5: " + str(e) + " Event: " + str(query_process))

                try:  # Action
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                   " VALUES ('{}','{}','{}','{}');".format(
                        event["UtcTime"],
                        "ProcessTerminated",
                        (event["Image"]).lower(),
                        (event["Image"]).lower())
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 5: " + str(e) + " Event: " + str(query_action))

            #  Kernel driver loaded
            if event["idEvent"] == 6:
                logger.info("ToDo")

            #  Image loaded
            if event["idEvent"] == 7:
                try:  # Process
                    insert_process(cursor, event)
                except Exception as e:
                    print("Error query_sprocess 7: " + str(e) + " Event: " + str(query_sprocess))

                try:  # File
                    if "Description" not in event:
                        event["Description"] = ""
                    if "Signature" not in event:
                        event["Signature"] = ""
                    if "OriginalFileName" not in event:
                        event["OriginalFileName"] = ""

                    query_file = 'INSERT INTO public."Files" ("Filename","FileVersion","Description","Product","Company","OriginalFileName","Hashes","Signed","Signature","SignatureStatus") ' \
                                 " VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}') ON CONFLICT" \
                                 ' ("Filename") DO UPDATE SET' \
                                 ' "FileVersion" = EXCLUDED."FileVersion", "Description" = EXCLUDED."Description",' \
                                 ' "Product" =  EXCLUDED."Product", "Company" = EXCLUDED."Company",' \
                                 '"OriginalFileName" = EXCLUDED."OriginalFileName","Hashes" = EXCLUDED."Hashes"' \
                                 ',"Signed" = EXCLUDED."Signed","Signature" = EXCLUDED."Signature",' \
                                 '"SignatureStatus" = EXCLUDED."SignatureStatus";'.format(
                        "f:" + str(event["ImageLoaded"]).lower(),
                        event["FileVersion"],
                        event["Description"],
                        event["Product"],
                        event["Company"],
                        event["OriginalFileName"],
                        event["Hashes"],
                        event["Signed"],
                        event["Signature"],
                        event["SignatureStatus"])
                    cursor.execute(query_file)
                except Exception as e:
                    print("Error query_file 7: " + str(e) + " Event: " + str(query_file))

                try:  # Action
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                   " VALUES ('{}','{}','{}','{}');".format(
                        event["UtcTime"],
                        "LoadImage",
                        "f:" + str(event["ImageLoaded"]).lower(),
                        (event["Image"]).lower())
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 7: " + str(e) + " Event: " + str(query_action))

            # Create Remote Thread
            if event["idEvent"] == 8:
                try:  # Source Process
                    query_sprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image")' \
                                     " VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;" \
                        .format((event["SourceImage"]).lower(),
                                event["SourceProcessId"],
                                (event["SourceImage"]).lower())
                    cursor.execute(query_sprocess)

                except Exception as e:
                    print("Error query_sprocess 8: " + str(e) + " Event: " + str(query_sprocess))

                try:  # Target Process
                    query_tprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                     "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                        (event["TargetImage"]).lower(),
                        event["TargetProcessId"],
                        (event["TargetImage"]).lower())
                    cursor.execute(query_tprocess)

                except Exception as e:
                    print("Error query_tprocess 8: " + str(e) + " Event: " + str(query_tprocess))

                try:  # Thread
                    thread_key = str(event["TargetProcessGuid"]) + ":" + str(
                        event["NewThreadId"])
                    query_thread = 'INSERT INTO public."Threads" ("ThreadId","ThreadNId","ProcessGuid","StartAddress",' \
                                   '"StartModule", "StartFunction")' \
                                   " VALUES ('{}','{}','{}','{}','{}','{}') ON CONFLICT " \
                                   '("ThreadId") DO UPDATE SET "StartAddress" = ' \
                                   'EXCLUDED."StartAddress", "StartModule"' \
                                   ' = EXCLUDED."StartModule", "StartFunction"' \
                                   ' = EXCLUDED."StartFunction";'.format(
                        thread_key,
                        event["NewThreadId"],
                        (event["TargetImage"]).lower(),
                        event["StartAddress"],
                        event["StartModule"],
                        event["StartFunction"])
                    cursor.execute(query_thread)

                except Exception as e:
                    print("Error query_thread 8: " + str(e) + " Event: " + str(query_thread))

                try:  # Action
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                   " VALUES ('{}','{}','{}','{}');".format(
                        event["UtcTime"],
                        "CreateRemoteThread",
                        (event["SourceImage"]).lower(),
                        thread_key)
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 8: " + str(e) + " Event: " + str(query_action))

            # Raw access read
            if event["idEvent"] == 9:
                logger.info("ToDo")

            #  Process Access
            if event["idEvent"] == 10:
                try:
                    query_pprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                     "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                        (event["SourceImage"]).lower(),
                        event["SourceProcessId"],
                        (event["SourceImage"]).lower())
                    cursor.execute(query_pprocess)
                except Exception as e:
                    logger.error("Error query_Pprocess 10: " + str(e) + " Event: " + str(query_pprocess))

                try:
                    query_tprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                     "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                        (event["TargetImage"]).lower(),
                        event["TargetProcessId"],
                        (event["TargetImage"]).lower())
                    cursor.execute(query_tprocess)
                except Exception as e:
                    logger.error("Error query_tprocess 10: " + str(e) + " Event: " + str(query_tprocess))
                """
                try:  # File - Actions
                    dlls = str(event["CallTrace"]).split("|")
                    for dll in dlls:
                        path = dll.split("+")
                        if (path[0]).lower() not in (event["SourceImage"]).lower():
                            query_file = 'INSERT INTO public."Files" ("Filename") ' \
                                           "VALUES ('{}') ON CONFLICT DO NOTHING;".format(
                                            "f:" + str(path[0]).lower())
                            cursor.execute(query_file)

                            query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                           " VALUES ('{}','{}','{}','{}');".format(
                                event["UtcTime"],
                                "LoadImage",
                                "f:" + str(path[0]).lower(),
                                (event["SourceImage"]).lower())
                            cursor.execute(query_action)

                except Exception as e:
                    print("Error query_file 10: " + str(e) + " Event: " + str(query_file))



                try:  # Thread
                    thread = str(event["SourceThreadId"]) + str(event["SourceProcessGUID"])
                    if thread not in threads_inserted:
                        thread_key += 1
                        query_thread = 'INSERT INTO public."Threads" ("ThreadId","ThreadNId","ProcessGuid")' \
                                       " VALUES ({},{},'{}') ON CONFLICT DO NOTHING;".format(
                                        thread_key,
                                        event["SourceThreadId"],
                                        event["SourceProcessGUID"])
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
                        event["UtcTime"], "ProcessAccess",
                        (event["SourceImage"]).lower(),
                        (event["TargetImage"]).lower(),
                        event["GrantedAccess"],
                        event["CallTrace"])
                    cursor.execute(query_action)
                except Exception as e:
                    logger.error("Error query_action 10: " + str(e) + " Event: " + str(query_action))

            #  File create
            if event["idEvent"] == 11:  # Create File

                try:  # Process
                    insert_process(cursor, event)
                except Exception as e:
                    print("Error query_sprocess 11: " + str(e) + " Event: " + str(event["Event"]))

                try:  # File
                    query_file = 'INSERT INTO public."Files" ("Filename","CreationUtcTime") ' \
                                 "VALUES ('{}','{}') ON CONFLICT DO NOTHING;".format(
                        "f:" + str(event["TargetFilename"]).lower(),
                        event["CreationUtcTime"])
                    cursor.execute(query_file)
                except Exception as e:
                    print("Error query_file 11: " + str(e) + " Event: " + str(query_file))

                try:  # Action
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                   " VALUES ('{}','{}','{}','{}');".format(
                        event["UtcTime"],
                        "CreateFile",
                        (event["Image"]).lower(),
                        "f:" + str(event["TargetFilename"]).lower())
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 11: " + str(e) + " Event: " + str(query_action))

            # Registry Key Operation
            if event["idEvent"] == 12 or event["idEvent"] == 13 \
                    or event["idEvent"] == 14:

                if event["TargetObject"]:
                    event["TargetObject"] = str(
                        event["TargetObject"]).replace("'", "\"")

                try:  # Process
                    insert_process(cursor, event)
                except Exception as e:
                    print("Error query_process 12-13-14: " + str(e) + " Event: " + str(event["Event"]))

                try:  # RegistryKey
                    if event["idEvent"] == 13:
                        if event["Details"]:
                            event["Details"] = str(
                                event["Details"]).replace("'", "\"")

                        query_key = 'INSERT INTO public."RegistryKeys" ("Key","Details") ' \
                                    "VALUES ('{}','{}') ON CONFLICT DO NOTHING;".format(
                            event["TargetObject"],
                            event["Details"])
                    else:
                        query_key = 'INSERT INTO public."RegistryKeys" ("Key") ' \
                                    "VALUES ('{}') ON CONFLICT DO NOTHING;".format(
                            event["TargetObject"])
                    cursor.execute(query_key)
                except Exception as e:
                    print("Error query_key 12-13-14: " + str(e) + " Event: " + str(query_key))

                try:  # Action
                    if "SetValue" in event["EventType"]:
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId","ExtraInfo")' \
                                       " VALUES ('{}','{}','{}','{}','{}');".format(
                            event["UtcTime"],
                            "RegistryKey-" + event["EventType"],
                            (event["Image"]).lower(),
                            event["TargetObject"],
                            event["Details"])
                    else:
                        query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                       " VALUES ('{}','{}','{}','{}');".format(
                            event["UtcTime"],
                            "RegistryKey-" + event["EventType"],
                            (event["Image"]).lower(),
                            event["TargetObject"])
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 12-13-14: " + str(e) + " Event: " + str(query_action))

            #  File create stream hash
            if event["idEvent"] == 15:
                logger.info("ToDo")

            #  File create stream hash
            if event["idEvent"] == 15:
                logger.info("ToDo")

            # Pipe event
            if event["idEvent"] == 17 or event["idEvent"] == 18:
                if event["idEvent"] == 17 and "EventType" not in event:
                    event["EventType"] = "CreatePipe"
                elif event["idEvent"] == 18 and "EventType" not in event:
                    event["EventType"] = "ConnectPipe"
                try:
                    insert_process(cursor, event)
                except Exception as e:
                    print("Error insert_process 17-18: " + str(e) + " Event: " + str(event["Event"]))

                try:  # Pipe
                    if event["PipeName"] not in pipes_inserted:
                        query_pipe = 'INSERT INTO public."Pipes" ("PipeName") ' \
                                     "VALUES ('{}');".format(
                            event["PipeName"])
                        cursor.execute(query_pipe)
                        pipes_inserted.append(event["PipeName"])
                except Exception as e:
                    print("Error query_file 17-18: " + str(e) + " Event: " + str(query_pipe))

                try:  # Action
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                   " VALUES ('{}','{}','{}','{}');".format(
                        event["UtcTime"],
                        event["EventType"],
                        (event["Image"]).lower(),
                        event["PipeName"])
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 17-18: " + str(e) + " Event: " + str(query_action))

            # WMI event
            if event["idEvent"] == 19 or event["idEvent"] == 20 \
                    or event["idEvent"] == 21:
                logger.info("ToDo")

            #  DNS
            if event["idEvent"] == 22:
                try:
                    insert_process(cursor, event)
                except Exception as e:
                    print("Error insert_process 22: " + str(e) + " Event: " + str(event["Event"]))

                try:  # Query
                    query_dnsquery = 'INSERT INTO public."DNSQuery" ("QueryName") ' \
                                     "VALUES ('{}') ON CONFLICT DO NOTHING;".format(
                        event["QueryName"])
                    cursor.execute(query_dnsquery)
                except Exception as e:
                    print("Error query_file 22: " + str(e) + " Event: " + str(query_dnsquery))

                try:  # Resolution
                    query_dnsresolution = 'INSERT INTO public."DNSResolution" ("UtcTime","QueryName","QueryStatus","QueryResults") ' \
                                          "VALUES ('{}','{}','{}','{}') ON CONFLICT DO NOTHING;".format(
                        event["UtcTime"],
                        event["QueryName"],
                        event["QueryStatus"],
                        event["QueryResults"])
                    cursor.execute(query_dnsresolution)
                except Exception as e:
                    print("Error query_file 22: " + str(e) + " Event: " + str(query_dnsresolution))

                try:  # Action
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                   " VALUES ('{}','{}','{}','{}') ;".format(
                        event["UtcTime"],
                        "DnsRequest",
                        (event["Image"]).lower(),
                        event["QueryName"])
                    cursor.execute(query_action)
                except Exception as e:
                    print("Error query_action 22: " + str(e) + " Event: " + str(query_action))


    cursor.close()
    end = time.time()
    print("Time to process file %s seconds ---" % (end - start))
    return True
