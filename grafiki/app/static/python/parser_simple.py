from evtx import PyEvtxParser
import json
from .src.database import sql_initialitation, sql_execute, sql_connection, sql_todisk, sql_execute_select
import logging
from django.db import transaction

# Basic configuration for logging
logging.basicConfig(format='%(name)s | %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def insert_process(cursor, event):
    query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                        "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                            (event["Event"]["EventData"]["Image"]).lower(),
                            event["Event"]["EventData"]["ProcessId"],
                            event["Event"]["EventData"]["Image"])
    cursor.execute(query_process)


def parser_simple(path, opath=None):
    import time
    cursor = sql_connection()
    sql_initialitation(cursor)
    parser = PyEvtxParser(path)
    connections_key = 100000000
    thread_key = 0
    files_inserted = []
    full_process_inserted = []
    pipes_inserted = []
    threads_inserted = []
    start = time.time()

    for record in parser.records_json():

        event = json.loads(record['data'])
        # Process Creation

        if event["Event"]["System"]["EventID"] == 1:
            try:
                if event["Event"]["EventData"]["ProcessGuid"] not in full_process_inserted:
                    #print("Full inserted")
                    query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image","IntegrityLevel",' \
                                    '"TerminalSessionId", "User")' \
                                    " VALUES ('{}','{}','{}','{}','{}', '{}')" \
                                    ' ON CONFLICT ("ProcessGuid") DO UPDATE SET "IntegrityLevel" = ' \
                                    'EXCLUDED."IntegrityLevel", "TerminalSessionId"' \
                                    ' = EXCLUDED."TerminalSessionId", "User" =  EXCLUDED."User";'.format(
                                        (event["Event"]["EventData"]["Image"]).lower(),
                                        event["Event"]["EventData"]["ProcessId"],
                                        event["Event"]["EventData"]["Image"],
                                        event["Event"]["EventData"]["IntegrityLevel"],
                                        event["Event"]["EventData"]["TerminalSessionId"],
                                        event["Event"]["EventData"]["User"])
                    cursor.execute(query_process)
                    full_process_inserted.append(event["Event"]["EventData"]["ProcessGuid"])

            except Exception as e:
                logger.error("Error query_process 1: " + str(e) + " Event: " + str(event["Event"]))

            try:
                if event["Event"]["EventData"]["Image"] not in files_inserted:
                    if "OriginalFileName" in event["Event"]["EventData"]:
                        original = ",'" + str(event["Event"]["EventData"]["OriginalFileName"]) + "'"
                        key = ',"OriginalFileName"'
                    else:

                        original = ""
                        key = ""

            except Exception as e:
                logger.error("Error query_file 1: " + str(e) + " Event: " + str(event["Event"]))

            try:
                query_pprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                 "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                                                                (event["Event"]["EventData"]["ParentImage"]).lower(),
                                                                event["Event"]["EventData"]["ParentProcessId"],
                                                                event["Event"]["EventData"]["ParentImage"])
                cursor.execute(query_pprocess)

            except Exception as e:
                logger.error("Error query_pprocess_exist 1: " + str(e) + " Event: " + str(query_pprocess))

            try:
                if event["Event"]["EventData"]["CommandLine"]:
                    event["Event"]["EventData"]["CommandLine"] = str(
                        event["Event"]["EventData"]["CommandLine"]).replace("'", "\"")

                if event["Event"]["EventData"]["CurrentDirectory"]:
                    event["Event"]["EventData"]["CurrentDirectory"] = str(
                        event["Event"]["EventData"]["CurrentDirectory"]).replace("'", "\"")

                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","LogonGuid","DestinationId",' \
                               '"ExtraInfo","ExtraInfo2")' \
                               " VALUES ('{}','{}','{}','{}','{}','{}','{}');".format(
                                                            event["Event"]["EventData"]["UtcTime"], "CreateProcess",
                                                            (event["Event"]["EventData"]["ParentImage"]).lower(),
                                                            event["Event"]["EventData"]["LogonGuid"],
                                                            (event["Event"]["EventData"]["Image"]).lower(),
                                                            event["Event"]["EventData"]["CommandLine"],
                                                            event["Event"]["EventData"]["CurrentDirectory"])
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 1: " + str(e) + " Event: " + str(query_action))

            try:
                query_user = 'INSERT INTO public."Users" ("LogonGuid","Name","LogonId","TerminalSessionId") VALUES' \
                             " ('{}','{}','{}',{}) ON CONFLICT DO NOTHING;".format(event["Event"]["EventData"]["LogonGuid"],
                                                            event["Event"]["EventData"]["User"],
                                                            event["Event"]["EventData"]["LogonId"],
                                                            event["Event"]["EventData"]["TerminalSessionId"])
                cursor.execute(query_user)
            except Exception as e:
                logger.error("Error 1: " + str(e) + " Event: " + str(query_user))

        # File creation time changed
        if event["Event"]["System"]["EventID"] == 2:
            logger.info("ToDo")

        # Network connection
        if event["Event"]["System"]["EventID"] == 3:
            try:

                connections_key = str(event["Event"]["EventData"]["SourceIp"])+str(event["Event"]["EventData"]["DestinationIp"])
                query_connection = 'INSERT INTO public."Connections" ("ConnectionId","Protocol","SourceIp","SourceHostname",' \
                                   '"SourcePort","DestinationIsIpv6","DestinationIp","DestinationHostname","DestinationPort") ' \
                                   "VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}') ON CONFLICT DO NOTHING;".format(
                                    connections_key, event["Event"]["EventData"]["Protocol"],
                                    event["Event"]["EventData"]["SourceIp"],
                                    event["Event"]["EventData"]["SourceHostname"],
                                    event["Event"]["EventData"]["SourcePort"],
                                    event["Event"]["EventData"]["DestinationIsIpv6"],
                                    event["Event"]["EventData"]["DestinationIp"],
                                    event["Event"]["EventData"]["DestinationHostname"],
                                    event["Event"]["EventData"]["DestinationPort"])
                cursor.execute(query_connection)
            except Exception as e:
                logger.error("Error query_connection 3: " + str(e) + " Event: " + str(query_connection))

            try:
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","LogonGuid","DestinationId",' \
                               '"ExtraInfo")' \
                               " VALUES ('{}','{}','{}','{}','{}','{}');".format(
                                event["Event"]["EventData"]["UtcTime"], "CreateConnection",
                                (event["Event"]["EventData"]["Image"]).lower(),
                                event["Event"]["EventData"]["User"],
                                connections_key,
                                event["Event"]["EventData"]["Initiated"])
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 3: " + str(e) + " Event: " + str(query_action))

            try:
                insert_process(cursor, event)
            except Exception as e:
                logger.error("Error query_pprocess_exist 3: " + str(e) + " Event: " + str(event["Event"]))

        # Process Terminated
        if event["Event"]["System"]["EventID"] == 5:
            try:  # Destination Process
                query_process = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                 "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                                    (event["Event"]["EventData"]["Image"]).lower(),
                                    event["Event"]["EventData"]["ProcessId"],
                                    event["Event"]["EventData"]["Image"])
                cursor.execute(query_process)

            except Exception as e:
                logger.error("Error query_sprocess 5: " + str(e) + " Event: " + str(query_process))

            try:  # Action
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                               " VALUES ('{}','{}','{}','{}');".format(
                                event["Event"]["EventData"]["UtcTime"],
                                "ProcessTerminated",
                                (event["Event"]["EventData"]["Image"]).lower(),
                                (event["Event"]["EventData"]["Image"]).lower())
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 5: " + str(e) + " Event: " + str(query_action))

        #  Kernel driver loaded
        if event["Event"]["System"]["EventID"] == 6:
            logger.info("ToDo")

        #  Image loaded
        if event["Event"]["System"]["EventID"] == 7:
            try:  # Process
                insert_process(cursor, event)
            except Exception as e:
                logger.error("Error query_sprocess 7: " + str(e) + " Event: " + str(query_sprocess))

            try:  # File
                if "Description" not in event["Event"]["EventData"]:
                    event["Event"]["EventData"]["Description"] = ""

                if "OriginalFileName" not in event["Event"]["EventData"]:
                    event["Event"]["EventData"]["OriginalFileName"] = ""

                query_file = 'INSERT INTO public."Files" ("Filename","FileVersion","Description","Product","Company","OriginalFileName","Hashes","Signed","Signature","SignatureStatus") ' \
                               " VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}') ON CONFLICT" \
                             ' ("Filename") DO UPDATE SET' \
                             ' "FileVersion" = EXCLUDED."FileVersion", "Description" = EXCLUDED."Description",' \
                             ' "Product" =  EXCLUDED."Product", "Company" = EXCLUDED."Company",' \
                             '"OriginalFileName" = EXCLUDED."OriginalFileName","Hashes" = EXCLUDED."Hashes"' \
                             ',"Signed" = EXCLUDED."Signed","Signature" = EXCLUDED."Signature",' \
                             '"SignatureStatus" = EXCLUDED."SignatureStatus";'.format(
                                "f:" + str(event["Event"]["EventData"]["ImageLoaded"]).lower(),
                                event["Event"]["EventData"]["FileVersion"],
                                event["Event"]["EventData"]["Description"],
                                event["Event"]["EventData"]["Product"],
                                event["Event"]["EventData"]["Company"],
                                event["Event"]["EventData"]["OriginalFileName"],
                                event["Event"]["EventData"]["Hashes"],
                                event["Event"]["EventData"]["Signed"],
                                event["Event"]["EventData"]["Signature"],
                                event["Event"]["EventData"]["SignatureStatus"])
                cursor.execute(query_file)
            except Exception as e:
                logger.error("Error query_file 7: " + str(e) + " Event: " + str(query_file))

            try:  # Action
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                               " VALUES ('{}','{}','{}','{}');".format(
                                event["Event"]["EventData"]["UtcTime"],
                                "LoadImage",
                                "f:" + str(event["Event"]["EventData"]["ImageLoaded"]).lower(),
                                (event["Event"]["EventData"]["Image"]).lower())
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 7: " + str(e) + " Event: " + str(query_action))

        # Create Remote Thread
        if event["Event"]["System"]["EventID"] == 8:
            try:  # Source Process
                query_sprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image")' \
                                 " VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;"\
                    .format((event["Event"]["EventData"]["SourceImage"]).lower(),
                            event["Event"]["EventData"]["SourceProcessId"],
                            (event["Event"]["EventData"]["SourceImage"]).lower())
                cursor.execute(query_sprocess)

            except Exception as e:
                logger.error("Error query_sprocess 8: " + str(e) + " Event: " + str(query_sprocess))

            try:  # Target Process
                query_tprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                 "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                                    (event["Event"]["EventData"]["TargetImage"]).lower(),
                                    event["Event"]["EventData"]["TargetProcessId"],
                                    (event["Event"]["EventData"]["TargetImage"]).lower())
                cursor.execute(query_tprocess)

            except Exception as e:
                logger.error("Error query_tprocess 8: " + str(e) + " Event: " + str(query_tprocess))

            try:  # Thread
                thread_key = str(event["Event"]["EventData"]["TargetProcessGuid"]) + ":" + str(event["Event"]["EventData"]["NewThreadId"])
                query_thread = 'INSERT INTO public."Threads" ("ThreadId","ThreadNId","ProcessGuid","StartAddress",' \
                               '"StartModule", "StartFunction")' \
                                " VALUES ('{}','{}','{}','{}','{}','{}') ON CONFLICT " \
                                '("ThreadId") DO UPDATE SET "StartAddress" = ' \
                                'EXCLUDED."StartAddress", "StartModule"' \
                                ' = EXCLUDED."StartModule", "StartFunction"' \
                                ' = EXCLUDED."StartFunction";'.format(
                                thread_key,
                                event["Event"]["EventData"]["NewThreadId"],
                                (event["Event"]["EventData"]["TargetImage"]).lower(),
                                event["Event"]["EventData"]["StartAddress"],
                                event["Event"]["EventData"]["StartModule"],
                                event["Event"]["EventData"]["StartFunction"])
                cursor.execute(query_thread)

            except Exception as e:
                logger.error("Error query_thread 8: " + str(e) + " Event: " + str(query_thread))

            try:  # Action
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                               " VALUES ('{}','{}','{}','{}');".format(
                                event["Event"]["EventData"]["UtcTime"],
                                "CreateRemoteThread",
                                (event["Event"]["EventData"]["SourceImage"]).lower(),
                                thread_key)
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 8: " + str(e) + " Event: " + str(query_action))

        # Raw access read
        if event["Event"]["System"]["EventID"] == 9:
            logger.info("ToDo")

        #  Process Access
        if event["Event"]["System"]["EventID"] == 10:
            try:
                query_pprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                 "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                                    (event["Event"]["EventData"]["SourceImage"]).lower(),
                                    event["Event"]["EventData"]["SourceProcessId"],
                                    (event["Event"]["EventData"]["SourceImage"]).lower())
                cursor.execute(query_pprocess)
            except Exception as e:
                logger.error("Error query_Pprocess 10: " + str(e) + " Event: " + str(query_pprocess))

            try:
                query_tprocess = 'INSERT INTO public."Processes" ("ProcessGuid","ProcessId","Image") ' \
                                 "VALUES ('{}',{},'{}') ON CONFLICT DO NOTHING;".format(
                                    (event["Event"]["EventData"]["TargetImage"]).lower(),
                                    event["Event"]["EventData"]["TargetProcessId"],
                                    (event["Event"]["EventData"]["TargetImage"]).lower())
                cursor.execute(query_tprocess)
            except Exception as e:
                logger.error("Error query_tprocess 10: " + str(e) + " Event: " + str(query_tprocess))
            try:
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId",' \
                               '"ExtraInfo","ExtraInfo2")' \
                               " VALUES ('{}','{}','{}','{}','{}','{}');".format(
                                event["Event"]["EventData"]["UtcTime"], "ProcessAccess",
                                (event["Event"]["EventData"]["SourceImage"]).lower(),
                                (event["Event"]["EventData"]["TargetImage"]).lower(),
                                event["Event"]["EventData"]["GrantedAccess"],
                                event["Event"]["EventData"]["CallTrace"])
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 10: " + str(e) + " Event: " + str(query_action))

        #  File create
        if event["Event"]["System"]["EventID"] == 11:  # Create File

            try:  # Process
                insert_process(cursor, event)
            except Exception as e:
                print("Error query_sprocess 11: " + str(e) + " Event: " + str(event["Event"]))

            try:  # File
                query_file = 'INSERT INTO public."Files" ("Filename","CreationUtcTime") ' \
                               "VALUES ('{}','{}') ON CONFLICT DO NOTHING;".format(
                                "f:" + str(event["Event"]["EventData"]["TargetFilename"]).lower(),
                                event["Event"]["EventData"]["CreationUtcTime"])
                cursor.execute(query_file)
            except Exception as e:
                logger.error("Error query_file 11: " + str(e) + " Event: " + str(query_file))

            try:  # Action
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                               " VALUES ('{}','{}','{}','{}');".format(
                                event["Event"]["EventData"]["UtcTime"],
                                "CreateFile",
                                (event["Event"]["EventData"]["Image"]).lower(),
                                "f:" + str(event["Event"]["EventData"]["TargetFilename"]).lower())
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 11: " + str(e) + " Event: " + str(query_action))

        # Registry Key Operation
        if event["Event"]["System"]["EventID"] == 12 or event["Event"]["System"]["EventID"] == 13 \
                or event["Event"]["System"]["EventID"] == 14:

            if event["Event"]["EventData"]["TargetObject"]:
                event["Event"]["EventData"]["TargetObject"] = str(
                    event["Event"]["EventData"]["TargetObject"]).replace("'", "\"")

            try:  # Process
                insert_process(cursor, event)
            except Exception as e:
                logger.error("Error query_process 12-13-14: " + str(e) + " Event: " + str(event["Event"]))

            try:  # RegistryKey
                if event["Event"]["System"]["EventID"] == 13:
                    if event["Event"]["EventData"]["Details"]:
                        event["Event"]["EventData"]["Details"] = str(
                            event["Event"]["EventData"]["Details"]).replace("'", "\"")

                    query_key = 'INSERT INTO public."RegistryKeys" ("Key","Details") ' \
                                "VALUES ('{}','{}') ON CONFLICT DO NOTHING;".format(
                                    event["Event"]["EventData"]["TargetObject"],
                                    event["Event"]["EventData"]["Details"])
                else:
                    query_key = 'INSERT INTO public."RegistryKeys" ("Key") ' \
                                 "VALUES ('{}') ON CONFLICT DO NOTHING;".format(event["Event"]["EventData"]["TargetObject"])
                cursor.execute(query_key)
            except Exception as e:
                logger.error("Error query_key 12-13-14: " + str(e) + " Event: " + str(query_key))

            try:  # Action
                if "SetValue" in event["Event"]["EventData"]["EventType"]:
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId","ExtraInfo")' \
                         " VALUES ('{}','{}','{}','{}','{}');".format(
                        event["Event"]["EventData"]["UtcTime"],
                        "RegistryKey-" + event["Event"]["EventData"]["EventType"],
                        (event["Event"]["EventData"]["Image"]).lower(),
                        event["Event"]["EventData"]["TargetObject"],
                        event["Event"]["EventData"]["Details"])
                else:
                    query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                                   " VALUES ('{}','{}','{}','{}');".format(
                        event["Event"]["EventData"]["UtcTime"],
                        "RegistryKey-" + event["Event"]["EventData"]["EventType"],
                        (event["Event"]["EventData"]["Image"]).lower(),
                        event["Event"]["EventData"]["TargetObject"])
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 12-13-14: " + str(e) + " Event: " + str(query_action))

        #  File create stream hash
        if event["Event"]["System"]["EventID"] == 15:
            logger.info("ToDo")

        #  File create stream hash
        if event["Event"]["System"]["EventID"] == 15:
            logger.info("ToDo")

        # Pipe event
        if event["Event"]["System"]["EventID"] == 17 or event["Event"]["System"]["EventID"] == 18:
            try:
                insert_process(cursor, event)
            except Exception as e:
                print("Error insert_process 17-18: " + str(e) + " Event: " + str(event["Event"]))

            try:  # Pipe
                if event["Event"]["EventData"]["PipeName"] not in pipes_inserted:
                    query_pipe = 'INSERT INTO public."Pipes" ("PipeName") ' \
                                   "VALUES ('{}');".format(
                                    event["Event"]["EventData"]["PipeName"])
                    cursor.execute(query_pipe)
                    pipes_inserted.append(event["Event"]["EventData"]["PipeName"])
            except Exception as e:
                logger.error("Error query_file 17-18: " + str(e) + " Event: " + str(query_pipe))

            try:  # Action
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                               " VALUES ('{}','{}','{}','{}');".format(
                                event["Event"]["EventData"]["UtcTime"],
                                event["Event"]["EventData"]["EventType"],
                                (event["Event"]["EventData"]["Image"]).lower(),
                                event["Event"]["EventData"]["PipeName"])
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 17-18: " + str(e) + " Event: " + str(query_action))

        # WMI event
        if event["Event"]["System"]["EventID"] == 19 or event["Event"]["System"]["EventID"] == 20 \
                or event["Event"]["System"]["EventID"] == 21:
            logger.info("ToDo")

        #  DNS
        if event["Event"]["System"]["EventID"] == 22:
            try:
                insert_process(cursor, event)
            except Exception as e:
                logger.error("Error insert_process 22: " + str(e) + " Event: " + str(event["Event"]))

            try:  # Query
                query_dnsquery = 'INSERT INTO public."DNSQuery" ("QueryName") ' \
                               "VALUES ('{}') ON CONFLICT DO NOTHING;".format(
                                event["Event"]["EventData"]["QueryName"])
                cursor.execute(query_dnsquery)
            except Exception as e:
                logger.error("Error query_file 22: " + str(e) + " Event: " + str(query_dnsquery))

            try:  # Resolution
                query_dnsresolution = 'INSERT INTO public."DNSResolution" ("UtcTime","QueryName","QueryStatus","QueryResults") ' \
                               "VALUES ('{}','{}','{}','{}') ON CONFLICT DO NOTHING;".format(
                                event["Event"]["EventData"]["UtcTime"],
                                event["Event"]["EventData"]["QueryName"],
                                event["Event"]["EventData"]["QueryStatus"],
                                event["Event"]["EventData"]["QueryResults"])
                cursor.execute(query_dnsresolution)
            except Exception as e:
                logger.error("Error query_file 22: " + str(e) + " Event: " + str(query_dnsresolution))

            try:  # Action
                query_action = 'INSERT INTO public."Actions" ("UtcTime","ActionType","ProcessGuid","DestinationId")' \
                               " VALUES ('{}','{}','{}','{}') ;".format(
                                event["Event"]["EventData"]["UtcTime"],
                                "DnsRequest",
                                (event["Event"]["EventData"]["Image"]).lower(),
                                event["Event"]["EventData"]["QueryName"])
                cursor.execute(query_action)
            except Exception as e:
                logger.error("Error query_action 22: " + str(e) + " Event: " + str(query_action))
    cursor.close()
    end = time.time()
    logger.info("Time to process file %s seconds ---" % (end - start))

