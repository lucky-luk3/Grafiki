from django.db import models


class Actions(models.Model):
    action_id = models.AutoField(primary_key=True, blank=False, null=False)
    utctime = models.DateTimeField(db_column='UtcTime', blank=True, null=True)
    actiontype = models.CharField(max_length=200, db_column='ActionType', blank=True, null=True)
    processguid = models.CharField(max_length=200, db_column='ProcessGuid', blank=True, null=True)
    logonguid = models.CharField(max_length=200, db_column='LogonGuid', blank=True, null=True)
    destinationid = models.CharField(max_length=2000, db_column='DestinationId', blank=True, null=True)
    extrainfo = models.CharField(max_length=8000, db_column='ExtraInfo', blank=True, null=True)
    extrainfo2 = models.CharField(max_length=8000, db_column='ExtraInfo2', blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'Actions'

    def __str__(self):
        field_values = []
        for field in self._meta.get_fields():
            field_values.append(str(getattr(self, field.name, '')))
        return ' '.join(field_values)


class Processes(models.Model):
    processguid = models.CharField(primary_key=True, max_length=200, db_column='ProcessGuid', blank=False, null=False, default=0)
    processid = models.IntegerField(db_column='ProcessId', blank=True, null=True)
    image = models.CharField(max_length=200, db_column='Image', blank=True, null=True)
    integritylevel = models.CharField(max_length=200, db_column='IntegrityLevel', blank=True, null=True, default="Null")
    terminalsessionid = models.IntegerField(db_column='TerminalSessionId', blank=True, null=True)
    user = models.CharField(db_column='User', max_length=100, null=True)
    computer = models.CharField(db_column='ComputerName', max_length=100, null=True)

    class Meta:
        managed = True
        db_table = 'Processes'

    def __str__(self):
        field_values = []
        for field in self._meta.get_fields():
            field_values.append(str(getattr(self, field.name, '')))
        return ' '.join(field_values)


class File(models.Model):
    name = models.CharField(max_length=100, null=False)
    evtx = models.FileField(upload_to='app/evtx/', null=False)
    processed = models.BooleanField(default=False, null=False)
    test = models.CharField(max_length=100, null=True)

    def __str__(self):
        return self.name

    def delete(self, *args, **kwargs):
        self.evtx.delete()
        super().delete(*args, **kwargs)

    class Meta:
        managed = True

CATEGORY_CHOICES = (('Other','Command_and_Control'),('Other','Command_and_Control'), ('Credential_Access','Credential_Access'), ('Defense_Evasion','Defense_Evasion'),
                    ('Discovery','Discovery'), ('Execution','Execution'), ('Lateral_Movement',"Lateral_Movement"), ('Persistence','Persistence'), ('Privilege_Escalation','Privilege_Escalation'))

class Example(models.Model):
    name = models.CharField(max_length=100, null=False)
    category = models.CharField(max_length=100, null=False, default="None", choices=CATEGORY_CHOICES)
    url = models.URLField(max_length=300, null=False)
    source = models.URLField(max_length=300, null=False)

    def __str__(self):
        return self.name

    class Meta:
        managed = True


class Connections(models.Model):
    connectionid = models.CharField(primary_key=True, db_column='ConnectionId', blank=True, null=False, max_length=200)
    protocol = models.CharField(max_length=200, db_column='Protocol', blank=True, null=True)
    sourceip = models.CharField(max_length=200, db_column='SourceIp', blank=True, null=True)
    sourcehostname = models.CharField(max_length=200, db_column='SourceHostname', blank=True, null=True)
    sourceport = models.CharField(max_length=200, db_column='SourcePort', blank=True, null=True)
    destinationisipv6 = models.CharField(max_length=200, db_column='DestinationIsIpv6', blank=True, null=True)
    destinationip = models.CharField(max_length=200, db_column='DestinationIp', blank=True, null=True)
    destinationhostname = models.CharField(max_length=200, db_column='DestinationHostname', blank=True, null=True)
    destinationport = models.CharField(max_length=200, db_column='DestinationPort', blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'Connections'


class Dnsquery(models.Model):
    queryname = models.CharField(primary_key=True, max_length=200, db_column='QueryName', blank=False, null=False, default= "")

    class Meta:
        managed = True
        db_table = 'DNSQuery'


class Dnsresolution(models.Model):
    id = models.AutoField(primary_key=True, db_column='id', blank=True, null=False, default=1)
    utctime = models.DateTimeField(db_column='UtcTime', blank=True, null=True)
    queryname = models.CharField(max_length=200, db_column='QueryName', blank=True, null=True)
    querystatus = models.CharField(max_length=200, db_column='QueryStatus', blank=True, null=True)
    queryresults = models.CharField(max_length=200, db_column='QueryResults', blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'DNSResolution'


class Files(models.Model):
    filename = models.CharField(primary_key=True, max_length=200, db_column='Filename', blank=False, null=False, default="0")
    originalfilename = models.CharField(max_length=200, db_column='OriginalFileName', blank=True, null=True)
    creationutctime = models.DateTimeField(db_column='CreationUtcTime', blank=True, null=True)
    description = models.CharField(max_length=200, db_column='Description', blank=True, null=True)
    company = models.CharField(max_length=200, db_column='Company', blank=True, null=True)
    hashes = models.CharField(max_length=200, db_column='Hashes', blank=True, null=True)
    signed = models.CharField(max_length=200, db_column='Signed', blank=True, null=True)
    signature = models.CharField(max_length=200, db_column='Signature', blank=True, null=True)
    signaturestatus = models.CharField(max_length=200, db_column='SignatureStatus', blank=True, null=True)
    product = models.CharField(max_length=200, db_column='Product', blank=True, null=True)
    fileversion = models.CharField(max_length=200, db_column='FileVersion', blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'Files'


class Pipes(models.Model):
    pipename = models.CharField(primary_key=True, max_length=200, db_column='PipeName', blank=False, null=False, default="")

    class Meta:
        managed = True
        db_table = 'Pipes'


class Registrykeys(models.Model):
    key = models.CharField(primary_key=True, max_length=8000, db_column='Key', blank=False, null=False, default=0)
    details = models.CharField(max_length=8000, db_column='Details', blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'RegistryKeys'

    def __str__(self):
        field_values = []
        for field in self._meta.get_fields():
            field_values.append(str(getattr(self, field.name, '')))
        return ' '.join(field_values)


class Threads(models.Model):
    threadid = models.CharField(primary_key=True, max_length=200, db_column='ThreadId', blank=False, null=False, default=0)
    threadnid = models.IntegerField(db_column='ThreadNId', blank=True, null=True)
    startaddress = models.CharField(max_length=200, db_column='StartAddress', blank=True, null=True)
    startmodule = models.CharField(max_length=200, db_column='StartModule', blank=True, null=True)
    startfunction = models.CharField(max_length=200, db_column='StartFunction', blank=True, null=True)
    processguid = models.CharField(max_length=200, db_column='ProcessGuid', blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'Threads'


class Users(models.Model):
    logonguid = models.CharField(primary_key=True,max_length=200, db_column='LogonGuid', blank=False, null=False, default="")
    name = models.CharField(max_length=200, db_column='Name', blank=True, null=True)
    logonid = models.CharField(max_length=200, db_column='LogonId', blank=True, null=True)
    terminalsessionid = models.IntegerField(db_column='TerminalSessionId', blank=True, null=True)
    userid = models.CharField(max_length=200, db_column='UserID', blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'Users'


class PSEvents(models.Model):
    id = models.AutoField(primary_key=True, db_column='id', blank=True, null=False, default=1)
    event_id = models.CharField(max_length=50, null=True)
    utctime = models.DateTimeField(db_column='UtcTime', blank=True, null=True)
    application = models.CharField(max_length=8000, null=True)
    param = models.CharField(max_length=8000, null=True)
    computer_name = models.CharField(max_length=200, null=True)


    class Meta:
        managed = True
        db_table = 'PSEvents'
