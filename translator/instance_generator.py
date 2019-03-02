'''
Generate instances of CDM Subjects, Principals, and Objects.
Store a map of the instances we've created with their uuids, so we can tell if
we already created a Record for a specific value (and get the uuid we generated
for that record)
'''

import logging
import subprocess
import uuid
from functools import lru_cache

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


    def __init__(self, _version):
        self.logger = logging.getLogger("tc")
        self.created_users = set()
        self.created_objects = set()
        self.updated_objects = set()

    def reset(self):
        self.created_users.clear()
        self.created_objects.clear()
        self.updated_objects.clear()
        self.remapped_objects.clear()
        self.netflow_counter = 0
        self.uuid_from_string.cache_clear()

    @lru_cache(maxsize=1024)
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
            id = uuid.uuid4().int
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

        record["source"] = source
        record["datum"] = subject

        record["type"] = "RECORD_SUBJECT"
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
#         principal["username"] = ""
        principal["groupIds"] = []
        principal["properties"] = {}

        # Save the uuid for this user
        self.created_users.add(uid)

        record["source"] = source
        record["datum"] = principal
        record["type"] = "RECORD_PRINCIPAL"
        return record

    def is_known_object(self, file_key):
        ''' Given a file uuid, did we create an object for the it already?
            If found, return true
        '''
        return file_key in self.created_objects

    def create_unix_socket_object(self, file_uuid, _host, source):
        ''' Infer the existence of a file object, add it to the created list, and return it.
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}

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

        record["source"] = source
        record["datum"] = fobject
        record["type"] = "RECORD_FILE_OBJECT"
        return record

    def create_pipe_object(self, ipc_uuid, _host, source):
        ''' Create one endpoint of a pipe.
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}

        fobject["baseObject"] = abstract_object
        fobject["uuid"] = self.uuid_from_string(ipc_uuid)
        fobject["type"] = "SRCSINK_IPC"

        # Save the uuid for this subject
        self.created_objects.add(ipc_uuid)

        record["source"] = source
        record["datum"] = fobject
        record["type"] = "RECORD_SRC_SINK_OBJECT"
        return record

    def create_file_object(self, file_uuid, _host, source, is_dir=False):
        ''' Infer the existence of a file object, add it to the created list, and return it.
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}

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

        record["source"] = source
        record["datum"] = fobject
        record["type"] = "RECORD_FILE_OBJECT"
        return record

    def create_netflow_object(self, dest_host, dest_port, socket_uuid, _host, source, local_host=None, local_port=None):
        ''' Infer the existence of a netflow object from a connection event with a addr and port key
            We always create a new netflow, so no need to look for an old uuid
        '''

        record = {}
        nobject = {}
        abstract_object = {}
        abstract_object["properties"] = {}

        nobject["baseObject"] = abstract_object
        nobject["localAddress"] = local_host
        nobject["localPort"] = local_port
        nobject["remoteAddress"] = dest_host
        nobject["remotePort"] = dest_port

        # Generate a uuid for this subject
        uniq = self.uuid_from_string(socket_uuid)
        self.netflow_counter += 1
        nobject["uuid"] = uniq

        record["source"] = source
        record["datum"] = nobject
        record["type"] = "RECORD_NET_FLOW_OBJECT"

        self.created_objects.add(socket_uuid)
        return record

    def create_unnamed_pipe_object(self, _host, endpoint1, endpoint2, source):
        ''' Create a host object, add it to the created list, and return it
        '''
        record = {}
        pipe = {}
        abstract_object = {}
        abstract_object["properties"] = {}

        pipe["baseObject"] = abstract_object
        pipe["uuid1"] = self.uuid_from_string(endpoint1)
        pipe["uuid2"] = self.uuid_from_string(endpoint2)
        pipe["uuid"] = self.create_uuid("netflow", endpoint1+endpoint2)
        pipe["type"] = "IPC_OBJECT_PIPE_UNNAMED"

        self.remapped_objects[uuid.UUID(endpoint1).int] = pipe["uuid"]
        self.remapped_objects[uuid.UUID(endpoint2).int] = pipe["uuid"]
        self.created_objects.add(str(uuid.UUID(bytes=pipe["uuid"])))
        self.created_objects.add(endpoint1)
        self.created_objects.add(endpoint2)

        record["source"] = source
        record["datum"] = pipe
        record["type"] = "RECORD_IPC_OBJECT"
        return record

    def create_host_object(self, host_uuid, host_type, hostname, uname, interfaces, version):
        ''' Create a host object, add it to the created list, and return it
        '''
        record = {}
        host = {}

        host["uuid"] = self.uuid_from_string(host_uuid)
        host["hostName"] = hostname
        host["hostIdentifiers"] = [] # values from `sysctl`?
# hostIdentifiers : array<HostIdentifier>
# HostIdentifier:
#   idType : string
#   idValue : string
        host["osDetails"] = uname
        host["hostType"] = host_type
        translator_date = subprocess.getoutput(['git log | awk \'/^Date: / {printf "%s %s %s %s",$6,$3,$4,$5; exit}\''])
        translator_rev = subprocess.getoutput(['git log | awk \'/^commit / {printf "%s",$2; exit}\''])
        host["ta1Version"] = version + "translator, "+translator_date + ", "+translator_rev + "; "

        host["interfaces"] = []
        for details in interfaces:
            interface = {}
            interface["name"] = details.get("name", "")
            interface["macAddress"] = details.get("mac", None)
            if not interface["macAddress"]:
                continue
            interface["ipAddresses"] = []
            inet = details.get("inet", None)
            inet6 = details.get("inet6", None)
            if inet:
                interface["ipAddresses"].append(inet)
            if inet6:
                interface["ipAddresses"].append(inet6)
            host["interfaces"].append(interface)
        record["datum"] = host
        record["type"] = "RECORD_HOST"
        self.created_objects.add(host_uuid)
        return record
