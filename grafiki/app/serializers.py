from .models import Processes, Actions, Connections, Dnsquery, Dnsresolution, Files, Pipes, Registrykeys, Threads, Users
from rest_framework import serializers


class ProcessSerializer(serializers.ModelSerializer):
    class Meta:
        model = Processes
        fields = "__all__"


class ActionsSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Actions
        fields = '__all__'


class ConnectionsSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Connections
        fields = "__all__"


class DNSquerySerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Dnsquery
        fields = "__all__"

class DNSresolutionSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    id = serializers.ReadOnlyField()
    class Meta:
        model = Dnsresolution
        fields = "__all__"


class FilesSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Files
        fields = "__all__"


class PipesSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Pipes
        fields = '__all__'


class RegistrykeysSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Registrykeys
        fields = ('key','details')


class ThreadsSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Threads
        fields = "__all__"


class UsersSerializer(serializers.ModelSerializer):
    #items = ProcessSerializer(many=True, read_only=True)
    class Meta:
        model = Users
        fields = "__all__"