from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.urlpatterns import format_suffix_patterns

from .views import *

urlpatterns = [
    path('', Home.as_view(), name='home'),
    path('processes/', ProcessFilter.as_view()),
    path('actions/', ActionsFilter.as_view()),
    path('connections/', ConnectionsFilter.as_view()),
    path('dnsquery/', DNSqueryFilter.as_view()),
    path('dnsresolution/', DNSresolutionFilter.as_view()),
    path('files/', FilesFilter.as_view()),
    path('pipes/', PipesFilter.as_view()),
    path('registrykeys/', RegistrykeysFilter.as_view()),
    path('threads/', ThreadsFilter.as_view()),
    path('users/', UsersFilter.as_view()),

    path('graph/', graph_list, name='graph'),
    path('examples/', examples_list, name='examples_list'),
    path('createexamples/', CreateExample.as_view(), name='create_example'),
    path('examples/<int:pk>/', delete_example, name='delete_example'),
    path('processexample/<int:pk>/', process_example, name='process_example'),
    path('processexamplesimple/<int:pk>/', process_example_simple, name='process_example_simple'),
    path('processbeat/<int:pk>/', process_beat, name='process_beat'),
    path('processbeatsimple/<int:pk>/', process_beat_simple, name='process_beat_simple'),
    path('menu/upload/', upload, name='upload'),
    path('menu/files/', file_list, name='file_list'),
    path('menu/files/upload/', upload_file, name='upload_file'),
    path('menu/files/<int:pk>/', delete_file, name='delete_file'),
    path('menu/processfile/<int:pk>/', process_file, name='process_file'),
    path('menu/processfilesimple/<int:pk>/', process_file_simple, name='process_file_simple'),
    path('elastic/', elastic_form, name='elastic_form'),

    path('class/files/', FileListView.as_view(), name='class_file_list'),
    path('class/files/upload/', UploadFileView.as_view(), name='class_upload_file'),
]


urlpatterns = format_suffix_patterns(urlpatterns)