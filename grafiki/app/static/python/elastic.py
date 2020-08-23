from elasticsearch_dsl import Search, connections, Q
from elasticsearch import Elasticsearch
import base64


def isBase64(sb):
    try:
        if isinstance(sb, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument isBase64 must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


def base64_in_application(s):
    words = s.split(" ")
    for word in words:
        if isBase64(word):
            decrypted = base64.b64decode(word).decode('UTF16')
            parsed = ps_beautify(decrypted)
            return parsed

def ps_beautify(s):
    i = 0
    s = list(s)
    for j in range(len(s)):
        if "{" in s[j]:
            i += 1
            s[j] = "{<br/>" + "&emsp;"*i

        if "}" in s[j]:
            i -= 1
            s[j] = "<br/>" + "&emsp;"*i + "}<br/>" + "&emsp;"*i

        if ";" in s[j]:
            s[j] = ";<br/>" + "&emsp;"*i

    s[0] = "<p>" + s[0]
    last = len(s) -1
    s[last] = s[last] + "</p>"
    s = "".join(s)
    s = s.replace("\'", "&quot;")
    return(s)



def crete_connection_sysmon():
    connections.create_connection(hosts=['192.168.129.137'], timeout=20)
    s = Search(index='logs-endpoint-winevent-sysmon*')
    return s

def es_get_all(date_from, date_to, filters="", options=""):
    client = Elasticsearch(hosts=[{"host" : "192.168.129.137", "port" : 9200}])
    s = Search(using=client, index='logs*')

    if date_from and date_to: #2018-04-29 09:02:26
        datef, timef = date_from.split(" ")
        datetimef = str(datef) + "T" + str(timef) + ".000Z"
        datet, timet = date_to.split(" ")
        datetimet = str(datet) + "T" + str(timet) + ".000Z"
        s = s.query('bool', filter=[Q('range', event_original_time={'gte': datetimef, 'lt': datetimet})])

    if filters:
        for e in filters:
            if "=" == filters[e]["operator"]:
                f = []
                o = filters[e]["text"].split(",")
                for option in o:
                    if len(f) == 0:
                        f.append(Q('match', **{filters[e]["element"]:option}))
                    else:
                        f[0] = f[0] | Q("match", **{filters[e]["element"]: option})
                s = s.query('bool', filter=f)
            elif "!=" == filters[e]["operator"]:
                f = []
                o = filters[e]["text"].split(",")
                for option in o:
                    if len(f) == 0:
                        f.append(~Q("match", **{filters[e]["element"]: option}))
                    else:
                        f[0] = f[0] | Q("match", **{filters[e]["element"]: option})
                s = s.query('bool', filter=f)

    total = s.count()
    s = s[0:total]
    response = s.execute()

    events = []
    for hit in response:
        event = {}
        j = hit.to_dict()
        if "powershell" in options and "Microsoft-Windows-PowerShell/Operational" in j["log_name"] or "sysmon" in options and "Sysmon" in j["log_name"]:
            event["event_id"] = j["event_id"]
            event["log_name"] = j["log_name"]  # "Microsoft-Windows-Sysmon/Operational"
            event["computer_name"] = j["host_name"]
            event["event_data"] = {}
            if "Sysmon" in j["log_name"]:
                if "event_original_message" in j:
                    lines = str(j["event_original_message"]).splitlines()
                    for line in lines:
                        elements = line.split(": ")
                        key = elements[0]
                        if len(elements) > 1:
                            value = elements[1]
                        else:
                            value = ""
                        event["event_data"][key] = value
                    events.append(event)
            elif "Microsoft-Windows-PowerShell/Operational" in j["log_name"]:
                try:
                    event["event_data"]["log_ingest_timestamp"] = j["log_ingest_timestamp"]
                    if "powershell" in j:
                        if "host" in j["powershell"]:
                            if "application" in j["powershell"]["host"]:
                                decrypted = base64_in_application(j["powershell"]["host"]["application"])
                                event["event_data"]["application"] = j["powershell"]["host"]["application"]
                                event["event_data"]["param"] = decrypted
                        elif "scriptblock" in j["powershell"]:
                            if "text" in j["powershell"]["scriptblock"]:
                                event["event_data"]["application"] = j["powershell"]["scriptblock"]["text"]
                                event["event_data"]["param"] = ""
                    elif "param1" in j:
                        event["event_data"]["param"] = ""
                        event["event_data"]["application"] = j["param1"]
                    elif "param2" in j:
                        event["event_data"]["param"] = ""
                        event["event_data"]["application"] = j["param2"]
                    events.append(event)
                except Exception as e:
                    print("Eception: {}, Event: {}".format(e, j))
    print(len(events))
    return events


