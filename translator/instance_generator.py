'''
Generate instances of CDM Subjects, Principals, and Objects.
Store a map of the instances we've created with their uuids, so we can tell if
we already created a Record for a specific value (and get the uuid we generated
for that record)
'''

import logging
import subprocess
import uuid

from tc.schema.records import record_generator

UID_NAMESPACE = uuid.UUID('6ba7b813-9dad-11d1-80b4-00c04fd430c8')
EVENT_NAMESPACE = uuid.UUID('6ba7b815-9dad-11d1-80b4-00c04fd430c8')
NETFLOW_NAMESPACE = uuid.UUID('6ba7b816-9dad-11d1-80b4-00c04fd430c8')
PIPE_NAMESPACE = uuid.UUID('6ba7b816-9dad-11d1-80b4-00c04fd430c8')

class InstanceGenerator():

    # set of known user UUIDs
    created_users = {}

    # Set of "file" UUIDs
    # Meaning normal files, but also processes
    created_objects = {}

    # Set of object UUIDs
    # Once in this set, we've filled out the object as best as we can - don't resend info
    updated_objects = {}

    remapped_objects = {}

    # Netflows are always created new, we don't refer to a previously created netflow object
    # So no need to store the uuids
    # Instead we just use a counter for the netflow uuid, since the host:port may not be unique
    #   (multiple connections to the same dest host:port)
    netflow_counter = 0

    CDMVersion = None

    def __init__(self, version):
        self.CDMVersion = version
        self.logger = logging.getLogger("tc")
        self.created_users = set()
        self.created_objects = set()
        self.updated_objects = set()
        self.host_created = False

    def reset(self):
        self.created_users.clear()
        self.created_objects.clear()
        self.updated_objects.clear()
        self.remapped_objects.clear()
        self.netflow_counter = 0
        self.host_created = False

    def uuid_from_string(self, data):
        return self.create_uuid("uuid", uuid.UUID(data).int)

    def create_uuid(self, object_type, data):
        ''' Create a unique ID from an object type
            ("pid" | "id" | "tid" | "event" | "file" | "netflow")
            and data value where the data value is the actual pid, tid, or userId value

            UUIDs are 128 bits

            For "uid", "event", "netflow", generate an RFC4122 v5 UUID
            for "uuid", we use given uuid (on pid, tid, file)
        '''
        if data in self.remapped_objects:
            return self.remapped_objects[data]

        id = 0
        if object_type == "uid":
            id = uuid.uuid5(UID_NAMESPACE, str(data)).int
        elif object_type == "event":
            id = uuid.uuid5(EVENT_NAMESPACE, str(data)).int
        elif object_type == "pipe":
            id = uuid.uuid5(NETFLOW_NAMESPACE, str(data)).int
        # XXX: Use socket UUIDs eventually
        elif object_type == "netflow":
            id = uuid.uuid5(NETFLOW_NAMESPACE, str(data)).int
        elif object_type == "uuid":
            id = data
        else:
            raise Exception("Unknown object type in create_uuid: "+object_type)

        return record_generator.Util.get_uuid_from_value(id)

    def create_process_subject(self, pid, puuid, ppuuid, principal, time_nanos, host, source):
        ''' Create a process subject, add it to the created list, and return it
        '''

        record = {}
        subject = {}

        subject["localPrincipal"] = self.create_uuid("uid", str(principal)+host)
        if ppuuid:
            subject["parentSubject"] = self.uuid_from_string(ppuuid)

        subject["cid"] = pid # relevent pid/tid/etc

        subject["startTimestampNanos"] = time_nanos
        subject["type"] = "SUBJECT_PROCESS"
        subject["hostId"] = self.uuid_from_string(host)
#         subject["unitId"] = int
#         subject["interation"] = int
#         subject["count"] = int
#         subject["cmdLine"] = string
#         subject["privilegeLevel"] = privilege level
#         subject["importedLibraries"] = [string]
#         subject["exportedLibraries"] = [string]
        subject["properties"] = {}
        subject["properties"]["host"] = host

        # Generate a uuid for this subject
        uniq = self.uuid_from_string(puuid)
        self.created_objects.add(puuid)
        subject["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = subject
        return record

    def get_user_id(self, uid):
        ''' Given a uid, did we create a Principal for that uid?
            If so, return true
        '''
        return uid in self.created_users

    def create_user_principal(self, uid, host, source):
        ''' Create a user principal, add it to the created list, and return it
        '''
        record = {}
        principal = {}
        principal["uuid"] = self.create_uuid("uid", str(uid)+host)
        principal["type"] = "PRINCIPAL_LOCAL"
        principal["userId"] = str(uid)
        principal["username"] = subprocess.getoutput(['id -un '+str(uid)])
        principal["groupIds"] = []
        principal["properties"] = {}
        principal["hostId"] = self.uuid_from_string(host)

        # Save the uuid for this user
        self.created_users.add(uid)

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = principal
        return record

    def is_known_object(self, file_key):
        ''' Given a file uuid, did we create an object for the it already?
            If found, return true
        '''
        return file_key in self.created_objects

    def create_unix_socket_object(self, file_uuid, host, source):
        ''' Infer the existence of a file object, add it to the created list, and return it.
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}
        abstract_object["hostId"] = self.uuid_from_string(host)

        fobject["baseObject"] = abstract_object
        fobject["type"] = "FILE_OBJECT_UNIX_SOCKET"
#         fobject["localPrincipal"] = uuid
#         fobject["size"] = int
#         fobject["fileDescriptor"] = int
#         fobject["peInfo"] = string
#         fobject["hashes"] = array of hashes
        fobject["uuid"] = self.uuid_from_string(file_uuid)


        # Save the uuid for this subject
        self.created_objects.add(file_uuid)

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = fobject
        return record

    def create_pipe_object(self, ipc_uuid, host, source):
        ''' Create one endpoint of a pipe.
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}
        abstract_object["hostId"] = self.uuid_from_string(host)

        fobject["baseObject"] = abstract_object
        fobject["uuid"] = self.uuid_from_string(ipc_uuid)
        fobject["type"] = "SRCSINK_IPC"

        # Save the uuid for this subject
        self.created_objects.add(ipc_uuid)

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = fobject
        return record

    def create_file_object(self, file_uuid, host, source, is_dir=False):
        ''' Infer the existence of a file object, add it to the created list, and return it.
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}
        abstract_object["hostId"] = self.uuid_from_string(host)

        fobject["baseObject"] = abstract_object
        if is_dir:
            fobject["type"] = "FILE_OBJECT_DIR"
        else:
            fobject["type"] = "FILE_OBJECT_FILE"
#         fobject["localPrincipal"] = uuid
#         fobject["size"] = int
#         fobject["fileDescriptor"] = int
#         fobject["peInfo"] = string
#         fobject["hashes"] = array of hashes
        fobject["uuid"] = self.uuid_from_string(file_uuid)

        # Save the uuid for this subject
        self.created_objects.add(file_uuid)

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = fobject
        return record

    def create_netflow_object(self, dest_host, dest_port, socket_uuid, host, source, local_host="localhost", local_port=-1):
        ''' Infer the existence of a netflow object from a connection event with a addr and port key
            We always create a new netflow, so no need to look for an old uuid
            For now, we don't have the local host or local port, so we use "localhost" and -1
        '''

        record = {}
        nobject = {}
        abstract_object = {}
        abstract_object["properties"] = {}
        abstract_object["hostId"] = self.uuid_from_string(host)

        nobject["baseObject"] = abstract_object
        nobject["localAddress"] = local_host
        nobject["localPort"] = local_port
        nobject["remoteAddress"] = dest_host
        nobject["remotePort"] = dest_port

        # Generate a uuid for this subject
        uniq = self.uuid_from_string(socket_uuid)
        self.netflow_counter += 1
        nobject["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = nobject

        self.created_objects.add(socket_uuid)
        return record

    def create_unnamed_pipe_object(self, host, endpoint1, endpoint2, source):
        ''' Create a host object, add it to the created list, and return it
        '''
        record = {}
        pipe = {}
        abstract_object = {}
        abstract_object["properties"] = {}
        abstract_object["hostId"] = self.uuid_from_string(host)

        pipe["baseObject"] = abstract_object
        pipe["sourceUUID"] = self.uuid_from_string(endpoint1)
        pipe["sinkUUID"] = self.uuid_from_string(endpoint2)
        pipe["uuid"] = self.create_uuid("netflow", endpoint1+endpoint2)

        self.remapped_objects[uuid.UUID(endpoint1).int] = pipe["uuid"]
        self.remapped_objects[uuid.UUID(endpoint2).int] = pipe["uuid"]
        self.created_objects.add(str(uuid.UUID(bytes=pipe["uuid"])))
        self.created_objects.add(endpoint1)
        self.created_objects.add(endpoint2)

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = pipe
        self.host_created = True
        return record

    def create_host_object(self, host_uuid, host_type, source):
        ''' Create a host object, add it to the created list, and return it
        '''
        record = {}
        host = {}

        host["uuid"] = self.uuid_from_string(host_uuid)
        host["hostName"] = subprocess.getoutput(['hostname'])
        host["hostIdentifiers"] = [] # values from `sysctl`?
# hostIdentifiers : array<HostIdentifier>
# HostIdentifier:
#   idType : string
#   idValue : string
        host["osDetails"] = subprocess.getoutput(['uname -m -r -s -v'])
        host["hostType"] = host_type
        host["interfaces"] = []
        for interface_name in subprocess.getoutput(['ifconfig -l']).split():
            interface = {}
            interface["name"] = interface_name
            interface["macAddress"] = subprocess.getoutput(['ifconfig '+interface_name+' | grep ether | awk \'{print $2}\''])
            if not interface["macAddress"]:
                continue
            interface["ipAddresses"] = []
            for ip_address in subprocess.getoutput(['ifconfig '+interface_name+' | grep \'\<inet.*\>\' | awk \'{print $2}\'']).split():
                interface["ipAddresses"].append(ip_address)
            host["interfaces"].append(interface)
        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = host
        self.host_created = True
        return record

