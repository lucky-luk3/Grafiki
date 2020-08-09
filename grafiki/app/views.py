import os
import string
from django.core.files.storage import FileSystemStorage
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.views.generic import TemplateView, ListView, CreateView
from rest_framework.views import APIView
from django.urls import reverse_lazy
from .models import *
from .serializers import *
from django.shortcuts import render, redirect
from rest_framework.response import Response
from .forms import FileForm
from .static.python.parser import parser
from .static.python.parser_simple import parser_simple
from .static.python.beat_parser import beat_parser
from .static.python.beat_parser_simple import beat_parser_simple
from .forms import ExampleForm
import json
import random
import urllib.request

DIR = '\\media\\app\\imgs\\'

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

class Home(TemplateView):
    template_name = 'home.html'

class Graph(TemplateView):
    template_name = 'graph.html'

class Upload_file(TemplateView):
    template_name = 'upload_file.html'


def graph_list(request):
    #psevents = PSEvents.objects.all()
    #for event in psevents:
        #event.utctime = event.utctime.strftime("%Y-%m-%d %H:%M:%S.%f")
    sessions = Processes.objects.order_by().values('terminalsessionid').distinct()
    integrities = Processes.objects.order_by().values('integritylevel').distinct()
    users = Processes.objects.order_by().values('user').distinct()
    #actions = Actions.objects.order_by().values('actiontype').distinct()
    edges_actions = actions_to_edges(request)
    edges_threads = threads_to_edges(request)
    edges_dnsresolutions = dnsresolutions_to_edges(request)
    edges_processes = process_to_edges(request)
    edges = edges_actions + edges_threads + edges_dnsresolutions + edges_processes
    data_edges = json.dumps(edges)
    nodes_actions = process_to_nodes(request)
    nodes_connections = connections_to_nodes(request)
    nodes_threads = threads_to_nodes(request)
    nodes_pipes = pipes_to_nodes(request)
    nodes_files = files_to_nodes(request)
    nodes_registrykeys = registrykeys_to_nodes(request)
    nodes_dnsqueries = dnsquery_to_nodes(request)
    nodes_dnsresolutions = dnsresolutions_to_nodes(request)
    nodes = nodes_actions + nodes_connections + nodes_threads + nodes_pipes + nodes_files + nodes_registrykeys + nodes_dnsqueries + nodes_dnsresolutions
    data_nodes = json.dumps(nodes)
    return render(request, 'graph2.html', {
        'sessions': sessions,
        'integrities': integrities,
        'users':users,
        'edges':data_edges,
        'nodes':data_nodes
        #'psevents':psevents
    })

def upload_file(request):
    if request.method == "POST":
        form = FileForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect(file_list)
    else:
        form = FileForm()
    return render(request, 'upload_file.html', {
        'form': form
    })

def delete_file(request, pk):
    if request.method == 'POST':
        book = File.objects.get(pk=pk)
        book.delete()
    return redirect(file_list)

def delete_example(request, pk):
    if request.method == 'POST':
        example = Example.objects.get(pk=pk)
        example.delete()
        path = "media\\app\\evtx\\" + str(example.name) + ".evtx"
        if os.path.isfile(path):
            os.remove(path)
    return redirect(examples_list)

def process_file(request, pk):
    if request.method == 'POST':
        file = File.objects.get(pk=pk)
        parser(file.evtx, str(file.name) + ".db")
    return redirect(graph_list)

def process_beat_simple(request, pk):
    if request.method == 'POST':
        file = File.objects.get(pk=pk)
        beat_parser_simple(file.evtx)
    return redirect(graph_list)

def process_beat(request, pk):
    if request.method == 'POST':
        file = File.objects.get(pk=pk)
        beat_parser(file.evtx)
    return redirect(graph_list)

def process_csv_simple(request, pk):
    if request.method == 'POST':
        file = File.objects.get(pk=pk)
        beat_parser_simple(file.evtx)
    return redirect(graph_list)

def process_csv(request, pk):
    if request.method == 'POST':
        file = File.objects.get(pk=pk)
        csv_parser(file.evtx)
    return redirect(graph_list)

def process_example(request, pk):
    if request.method == 'POST':
        example = Example.objects.get(pk=pk)
        url = example.url
        ext = url.split(".")[-1:][0]
        if "gz" in ext:
            ext = ".".join(url.split(".")[-2:])
        path = "media/app/evtx/" + str(example.name) + "." + str(ext)
        urllib.request.urlretrieve(url, path)
        output_path = ""
        if "evtx" in ext:
            parser(path)
        elif "tar.gz" in ext:
            import shutil
            output_path = "media/app/evtx"
            shutil.unpack_archive(path, output_path)
            for file in os.listdir(output_path):
                print("File processed: " + str(file))
                if file.startswith(example.name) and file.endswith(".json"):
                    output_path = output_path + "/" + file
                    response = beat_parser(output_path)
                    if not response:  # If error in parse redirect to example_list
                        return redirect(examples_list)

        os.remove(path)
        if output_path:
            os.remove(output_path)
        return redirect(graph_list)

def examples_list(request):
    examples = Example.objects.all()
    if not examples:
        examples = []
    return render(request, 'examples_list.html', {
        'examples': examples
    })

def elastic_form(request):
    context = {}
    if request.method == 'POST':

        date_from = request.POST['from']
        date_to = request.POST['to']
        if "elements" in request.POST:
            filters = {}
            l = len(request.POST.getlist('elements'))
            for i in range(0, l):
                filters[i] = {}
                filters[i]["element"] = request.POST.getlist("elements")[i]
                filters[i]["operator"] = request.POST.getlist("operators")[i]
                filters[i]["text"] = request.POST.getlist("text")[i]
            print(filters)
        else:
            filters = ""
        options = request.POST.getlist("options")
        if "simple" in options:
            beat_parser_simple("Null", True, date_from, date_to, filters, options)
        else:
            beat_parser("Null", True, date_from, date_to, filters, options)
        return redirect(graph_list)

    return render(request, 'elastic_form.html', context)

class CreateExample(CreateView):
    template_name = 'create_example.html'
    form_class = ExampleForm
    success_url = reverse_lazy('examples_list')

def process_example_simple(request, pk):
    if request.method == 'POST':
        example = Example.objects.get(pk=pk)
        url = example.url
        ext = url.split(".")[-1:][0]
        if "gz" in ext:
            ext = ".".join(url.split(".")[-2:])
        path = "media/app/evtx/" + str(example.name) + "." + str(ext)
        urllib.request.urlretrieve(url, path)
        if "evtx" in ext:
            parser_simple(path)
        elif "tar.gz" in ext:
            import shutil
            output_path = "media/app/evtx"
            shutil.unpack_archive(path, output_path)
            for file in os.listdir(output_path):
                if file.startswith(example.name) and file.endswith(".json"):
                    beat_parser_simple(output_path + "/" + file)
                    # Handle error when format it's not correct
    return redirect(graph_list)

def process_file_simple(request, pk):
    if request.method == 'POST':
        file = File.objects.get(pk=pk)
        print("File not processed jet: " + str(file.processed))
        parser_simple(file.evtx, str(file.name) + ".db")
    return redirect(graph_list)

class FileListView(ListView):
    model = File
    template_name = 'class_file_list.html'
    context_object_name = 'files'

class UploadFileView(CreateView):
    model = File
    form_class = FileForm
    success_url = reverse_lazy('class_file_list')
    template_name = 'upload_file.html'

def upload(request):
    context = {}
    if request.method == 'POST':
        uploaded_file = request.FILES['document']

        fs = FileSystemStorage()
        name = fs.save(uploaded_file.name, uploaded_file)
        context['url'] = fs.url(name)
    return render(request, 'upload.html', context)

def file_list(request):
    files = File.objects.all()
    return render(request, 'file_list.html', {
        'files': files
    })

def actions_to_edges(request):
    actions = Actions.objects.all()
    edges = []
    access_added = []
    connections_added = []
    created_added = []
    registry_key_added = []
    delete_added = []
    load_added = []
    for action in actions:
        edge = {}
        edge["id"] = action.action_id
        edge["from"] = action.processguid
        edge["to"] = action.destinationid
        edge["arrows"] = "to"
        edge["value"] = 1
        edge["title"] = "Events: " + str(edge["value"])
        edge["utctime"] = (action.utctime).strftime("%d/%m/%Y %H:%M:%S.%f")
        if "CreateProcess" in action.actiontype or "CreatePipe" in action.actiontype or\
                "CreateFile" in action.actiontype or "CreateFile" in action.actiontype or\
                "CreateRemoteThread" in action.actiontype or "RegistryKey-CreateKey" in action.actiontype:
            if (str(action.processguid) + str(action.destinationid)) not in created_added:
                edge["group"] = "create"
                created_added.append((str(action.processguid) + str(action.destinationid)))
            else:
                for edge in edges:
                    if (action.processguid in edge["from"]) and (action.destinationid in edge["to"]) and ("create" in edge["group"]) :
                        edge["value"] = edge["value"] + 1
                        edge["title"] = "Events: " + str(edge["value"])
                        break
                continue

        elif "CreateConnection" in action.actiontype or "ConnectPipe" in action.actiontype or "DnsRequest" in action.actiontype:
            if (str(action.processguid) + str(action.destinationid)) not in connections_added:
                edge["group"] = "connect"
                edge["color"] = '#FC08ED'
                connections_added.append(str(action.processguid) + str(action.destinationid))
            else:
                for edge in edges:
                    if (action.processguid in edge["from"]) and (action.destinationid in edge["to"]) and ("connect" in edge["group"]) :
                        edge["value"] = edge["value"] + 1
                        edge["title"] = "Events: " + str(edge["value"])
                        break
                continue
        elif "ProcessAccess" in action.actiontype:
            if (str(action.processguid) + str(action.destinationid)) not in access_added:
                edge["group"] = "access"
                edge["color"] = 'purple'
                access_added.append(str(action.processguid) + str(action.destinationid))
            else:
                for edge in edges:
                    if (action.processguid in edge["from"]) and (action.destinationid in edge["to"]) and ("access" in edge["group"]) :
                        edge["value"] = edge["value"] + 1
                        edge["title"] = "Events: " + str(edge["value"])
                        break
                continue
        elif "RegistryKey-SetValue" in action.actiontype:
            if (str(action.processguid) + str(action.destinationid)) not in registry_key_added:
                edge["group"] = "change"
                edge["color"]= 'orange'
                registry_key_added.append(str(action.processguid) + str(action.destinationid))
            else:
                for edge in edges:
                    if (action.processguid in edge["from"]) and (action.destinationid in edge["to"]) and ("RegistryKey-SetValue" in edge["group"]) :
                        edge["value"] = edge["value"] + 1
                        edge["title"] = "Events: " + str(edge["value"])
                        break
                continue
        elif "Delete" in action.actiontype:
            if (str(action.processguid) + str(action.destinationid)) not in delete_added:
                edge["group"] = "delete"
                edge["color"]= 'red'
                delete_added.append(str(action.processguid) + str(action.destinationid))
            else:
                for edge in edges:
                    if (action.processguid in edge["from"]) and (action.destinationid in edge["to"]) and ("Delete" in edge["group"]) :
                        edge["value"] = edge["value"] + 1
                        edge["title"] = "Events: " + str(edge["value"])
                        break
                continue
        elif "ProcessTerminate" in action.actiontype:
            if (str(action.processguid) + str(action.destinationid)) not in delete_added:
                edge["group"] = "finish"
                edge["color"]= 'red'
                delete_added.append(str(action.processguid) + str(action.destinationid))
            else:
                for edge in edges:
                    if (action.processguid in edge["from"]) and (action.destinationid in edge["to"]) and ("access" in edge["group"]) :
                        edge["value"] = edge["value"] + 1
                        edge["title"] = "Events: " + str(edge["value"])
                        break
                continue
        elif "LoadImage" in action.actiontype:
            if (str(action.processguid) + str(action.destinationid)) not in load_added:
                edge["group"] = "load"
                edge["color"]= 'grey'
                load_added.append(str(action.processguid) + str(action.destinationid))
            else:
                for edge in edges:
                    if (action.processguid in edge["from"]) and (action.destinationid in edge["to"]) and ("load" in edge["group"]) :
                        edge["value"] = edge["value"] + 1
                        edge["title"] = "Events: " + str(edge["value"])
                        break
                continue
        else:
            edge["group"] = action.actiontype

        edges.append(edge)
    return edges

def threads_to_edges(request):
    threads = Threads.objects.all()
    edges = []
    edges_added = []
    for thread in threads:
        if (str(thread.processguid) + str(thread.threadid)) not in edges_added:
            edge = {}
            edge["id"] = str(thread.processguid) + str(thread.threadid)
            edge["to"] = thread.processguid
            edge["from"] = thread.threadid
            edge["group"] = "owned"
            edge["arrows"] = "to"
            edge["color"] = 'green'
            action_source = Actions.objects.filter(Q(processguid=thread.threadid) | Q(destinationid=thread.threadid))
            if action_source:
                ids = []
                for action in action_source:
                    ids.append(action.action_id)
                ids.sort()
                for action in action_source:
                    if action.action_id == ids[0]:
                        edge["utctime"] = (action.utctime).strftime("%d/%m/%Y %H:%M:%S.%f")
                        break
            else:
                action_destination = Actions.objects.filter(destinationid=thread.threadid)
                for action in action_destination:
                    edge["utctime"] = (action.utctime).strftime("%d/%m/%Y %H:%M:%S.%f")
                    break

            edges.append(edge)
            edges_added.append(edge["id"])
    return(edges)

def dnsresolutions_to_edges(request):
    dnsresolutions = Dnsresolution.objects.all()
    edges = []
    dnsresolutions_added = []
    for dnsresolution in dnsresolutions:
        edge = {}
        edge["id"] = randomString(15)
        edge["from"] = dnsresolution.queryname
        edge["to"] = dnsresolution.queryresults
        edge["arrows"] = "to"
        edge["value"] = 1
        edge["title"] = "Events: " + str(edge["value"])
        edge["utctime"] = (dnsresolution.utctime).strftime("%d/%m/%Y %H:%M:%S.%f")
        if (str(dnsresolution.queryresults) + str(dnsresolution.queryname)) not in dnsresolutions_added:
            edge["group"] = "connect"
            edge["color"] = '#FC08ED'
            dnsresolutions_added.append(str(dnsresolution.queryresults) + str(dnsresolution.queryname))
        else:
            for edge in edges:
                if (dnsresolution.queryresults in edge["from"]) and (dnsresolution.queryname in edge["to"]) and (
                        "connect" in edge["group"]):
                    edge["value"] = edge["value"] + 1
                    edge["title"] = "Events: " + str(edge["value"])
                    break
            continue
        edges.append(edge)
    return(edges)

def process_to_edges(request):
    processes = Processes.objects.all()
    edges = []
    for process in processes:
        if process.computer:
            edge = {}
            edge["id"] = randomString(15)
            edge["to"] = process.computer
            edge["from"] = process.processguid
            edge["group"] = "owned"
            edge["arrows"] = "to"
            edge["color"] = 'green'
            action_source = Actions.objects.filter(Q(processguid=process.processguid) | Q(destinationid=process.processguid))
            if action_source:
                ids = []
                for action in action_source:
                    ids.append(action.action_id)
                ids.sort()
                for action in action_source:
                    if action.action_id == ids[0]:
                        edge["utctime"] = (action.utctime).strftime("%d/%m/%Y %H:%M:%S.%f")
                        break
            else:
                action_destination = Actions.objects.filter(destinationid=process.processguid)
                for action in action_destination:
                    edge["utctime"] = (action.utctime).strftime("%d/%m/%Y %H:%M:%S.%f")
                    break

            edges.append(edge)
    return (edges)

def process_to_nodes(request):
    processes = Processes.objects.all()
    nodes = []
    computers_added = []

    for process in processes:
        node = {}


        node["id"] = process.processguid
        node["integrity"] = process.integritylevel
        node["group"] = "process"
        label = (process.image).split("\\")[-1]
        node["label"] = label
        node["title"] = str(process.image)
        #node["shape"] = 'image'
        #node["image"] = DIR + 'letter-p.png'
        #node["view"] = "simple"
        nodes.append(node)


        if process.computer not in computers_added:
            node_computer = {}
            node_computer["id"] = process.computer
            node_computer["group"] = "computer"
            node_computer["label"] = process.computer
            node_computer["title"] = str(process.computer)
            nodes.append(node_computer)
            computers_added.append(process.computer)

    return (nodes)

def process_to_nodes_simple(request):
    processes = Processes.objects.all()
    nodes = []
    process_added = []
    for process in processes:
        if str(process.processguid).lower() not in process_added:
            node = {}
            node["id"] = process.processguid
            node["integrity"] = process.integritylevel
            if "System" in process.integritylevel:
                node["group"] = "system"
            else:
                node["group"] = "process"
            label = (process.image).split("\\")[-1]
            node["label"] = label
            node["title"] = str(process.image)
            nodes.append(node)
            process_added.append(str(process.processguid).lower())
    return (nodes)

def files_to_nodes(request):
    files = Files.objects.all()
    nodes = []
    files_added = []
    for file in files:
        if str(file.filename).lower() not in files_added:
            node = {}
            node["id"] = file.filename
            node["group"] = "file"
            label = (file.filename).split("\\")[-1]
            node["label"] = label
            node["title"] = str(file.filename)
            #node["shape"] = 'image'
            #node["image"] = DIR + 'paper.png'
            #node["view"] = "simple"
            nodes.append(node)
            files_added.append(str(file.filename).lower())

    return (nodes)

def connections_to_nodes(request):
    connections = Connections.objects.all()
    nodes = []
    for connection in connections:
        node = {}
        node["id"] = connection.connectionid
        node["label"] = connection.destinationip
        node["group"] = "connection"
        node["destinationport"] = connection.destinationport
        node["title"] = str(connection.destinationip) + ":" + str(connection.destinationport)
        nodes.append(node)
    return nodes

def threads_to_nodes(request):
    threads = Threads.objects.all()
    nodes = []
    nodes_added = []
    for thread in threads:
        if thread.threadid not in nodes_added:
            node = {}
            node["id"] = thread.threadid
            node["label"] = thread.threadnid
            node["group"] = "thread"
            node["process"] = thread.processguid
            node["title"] = thread.threadnid
            #node["view"] = "simple"
            nodes.append(node)
            nodes_added = thread.threadid


    return nodes

def pipes_to_nodes(request):
    pipes = Pipes.objects.all()
    nodes = []
    for pipe in pipes:
        node = {}
        node["id"] = pipe.pipename
        node["label"] = pipe.pipename
        node["group"] = "pipe"
        node["title"] = pipe.pipename
        nodes.append(node)
    return nodes

def registrykeys_to_nodes(request):
    registrykeys = Registrykeys.objects.all()
    nodes = []
    for registrykey in registrykeys:
        node = {}
        node["id"] = registrykey.key
        node["label"] = registrykey.key
        node["group"] = "registrykey"
        node["title"] = registrykey.details
        nodes.append(node)
    return nodes

def dnsquery_to_nodes(request):
    dnsqueries = Dnsquery.objects.all()
    nodes = []
    for dnsquery in dnsqueries:
        node = {}
        node["id"] = dnsquery.queryname
        node["label"] = dnsquery.queryname
        node["group"] = "dnsquery"
        node["title"] = dnsquery.queryname
        nodes.append(node)
    return nodes

def dnsresolutions_to_nodes(request):
    dnsresolutions = Dnsresolution.objects.all()
    nodes = []
    dnsresolutions_added = []
    for dnsresolution in dnsresolutions:
        if dnsresolution.queryresults not in dnsresolutions_added:
            node = {}
            node["id"] = dnsresolution.queryresults
            node["label"] = dnsresolution.queryresults
            node["group"] = "dnsresolution"
            node["title"] = str(dnsresolution.queryresults) + ": " + str(dnsresolution.queryresults)
            nodes.append(node)
            dnsresolutions_added.append(dnsresolution.queryresults)
    return nodes




class ProcessFilter(APIView):
    def get(self, request):
        if request.query_params:
            processes = Processes.objects.all()
            for key in request.query_params:
                processes = processes.filter(**{key: request.query_params[key]})
        else:
            processes = Processes.objects.all()
        serializer = ProcessSerializer(processes, many=True)
        return JsonResponse(serializer.data, safe=False)


class ActionsFilter(APIView):
    def get(self, request):
        if request.query_params:
            actions = Actions.objects.all()
            for key in request.query_params:
                actions = actions.filter(**{key: request.query_params[key]})
        else:
            actions = Actions.objects.all()
        serializer = ActionsSerializer(actions, many=True)
        return JsonResponse(serializer.data, safe=False)


class ConnectionsFilter(APIView):
    def get(self, request):
        if request.query_params:
            connections = Connections.objects.all()
            for key in request.query_params:
                connections = connections.filter(**{key: request.query_params[key]})
        else:
            connections = Connections.objects.all()
        serializer = ConnectionsSerializer(connections, many=True)
        return JsonResponse(serializer.data, safe=False)


class DNSqueryFilter(APIView):
    def get(self, request):
        if request.query_params:
            dnsquery = Dnsquery.objects.all()
            for key in request.query_params:
                dnsquery = dnsquery.filter(**{key: request.query_params[key]})
        else:
            dnsquery = Dnsquery.objects.all()
        serializer = DNSquerySerializer(dnsquery, many=True)
        return JsonResponse(serializer.data, safe=False)


class DNSresolutionFilter(APIView):
    def get(self, request):
        if request.query_params:
            dnsresolution = Dnsresolution.objects.all()
            for key in request.query_params:
                dnsresolution = dnsresolution.filter(**{key: request.query_params[key]})
        else:
            dnsresolution = Dnsresolution.objects.all()
        serializer = DNSresolutionSerializer(dnsresolution, many=True)
        return JsonResponse(serializer.data, safe=False)


class FilesFilter(APIView):
    def get(self, request):
        if request.query_params:
            files = Files.objects.all()
            for key in request.query_params:
                files = files.filter(**{key: request.query_params[key]})
        else:
            files = Files.objects.all()
        serializer = FilesSerializer(files, many=True)
        return JsonResponse(serializer.data, safe=False)


class PipesFilter(APIView):
    def get(self, request):
        if request.query_params:
            pipes = Pipes.objects.all()
            for key in request.query_params:
                pipes = pipes.filter(**{key: request.query_params[key]})
        else:
            pipes = Pipes.objects.all()
        serializer = PipesSerializer(pipes, many=True)
        return JsonResponse(serializer.data, safe=False)


class RegistrykeysFilter(APIView):
    def get(self, request):
        if request.query_params:
            registrykeys = Registrykeys.objects.all()
            for key in request.query_params:
                registrykeys = registrykeys.filter(**{key: request.query_params[key]})
        else:
            registrykeys = Registrykeys.objects.all()
        serializer = RegistrykeysSerializer(registrykeys, many=True)
        return JsonResponse(serializer.data, safe=False)


class ThreadsFilter(APIView):
    def get(self, request):
        if request.query_params:
            threads = Threads.objects.all()
            for key in request.query_params:
                threads = threads.filter(**{key: request.query_params[key]})
        else:
            threads = Threads.objects.all()
        serializer = ThreadsSerializer(threads, many=True)
        return JsonResponse(serializer.data, safe=False)


class UsersFilter(APIView):
    def get(self, request):
        if request.query_params:
            users = Users.objects.all()
            for key in request.query_params:
                users = users.filter(**{key: request.query_params[key]})
        else:
            users = Users.objects.all()
        serializer = UsersSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)