'''
Generate instances of CDM Subjects, Principals, and Objects.  
Store a map of the instances we've created with their uuids, so we can tell if
we already created a Record for a specific value (and get the uuid we generated
for that record)
'''

import logging
import uuid

from tc.schema.records import record_generator

UID_NAMESPACE =     uuid.UUID('6ba7b813-9dad-11d1-80b4-00c04fd430c8')
EVENT_NAMESPACE =   uuid.UUID('6ba7b815-9dad-11d1-80b4-00c04fd430c8')
NETFLOW_NAMESPACE = uuid.UUID('6ba7b816-9dad-11d1-80b4-00c04fd430c8')
PIPE_NAMESPACE =    uuid.UUID('6ba7b816-9dad-11d1-80b4-00c04fd430c8')

class InstanceGenerator():

    # Map to SUBJECT_PROCESS from process UUID
    created_processes = {}

    # Map to SUBJECT_THREAD from thread UUID
    created_threads = {}

    # Map to PRINCIPAL_LOCAL from uid
    created_users = {}

    # File Subjects
    created_files = {} # Key: "path", Value: {version : uuid} dict.
                    # Value is another dict of file version : uuid
                    # No need to store the file Objects themselves, we just store the generated uuid

    # Netflows are always created new, we don't refer to a previously created netflow object
    # So no need to store the uuids
    # Instead we just use a counter for the netflow uuid, since the host:port may not be unique
    #   (multiple connections to the same dest host:port)
    netflow_counter = 0
    # Pipes are always created new
    pipe_counter = 0

    CDMVersion = None

    def __init__(self, version):
        self.CDMVersion = version
        self.logger = logging.getLogger("tc")

    def reset(self):
        self.created_processes.clear()
        self.created_threads.clear()
        self.created_users.clear()
        self.created_files.clear()
        self.netflow_counter = 0
        self.pipe_counter = 0

    def create_uuid(self, object_type, data):
        ''' Create a unique ID from an object type ("pid" | "uid" | "tid" | "event" | "file" | "netflow") and data value
               where the data value is the actual pid, tid, or userId value

            UUIDs are now 128 bits

            For "uid", "event", "netflow", generate an RFC4122 v5 UUID
            for "uuid", we use given uuid (on pid, tid, file)
        '''
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

    def get_process_subject_id(self, puuid):
        ''' Given a pid, did we create a subject for the pid previously?
            If so return the uid of the subject, if not return None
        '''
        if puuid in self.created_processes:
            return self.created_processes[puuid]

        return None

    def create_process_subject(self, pid, puuid, ppuuid, principal, time_nanos, source):
        ''' Create a process subject, add it to the created list, and return it
        '''

        record = {}
        subject = {}

        subject["localPrincipal"] = self.create_uuid("uid", principal);
        if ppuuid:
                subject["parentSubject"] = self.create_uuid("uuid", uuid.UUID(ppuuid).int)

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

        # Generate a uuid for this subject
        if puuid == str(pid):
            uniq = self.create_uuid("pid", puuid)
        else:
            uniq = self.create_uuid("uuid", uuid.UUID(puuid).int)
        self.created_processes[puuid] = uniq
        subject["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = subject
        return record

    def get_thread_subject_id(self, tid):
        ''' Given a tid, did we create a subject for tid?
            If so, return the uid of the subject, if not return None
        '''
        if tid in self.created_threads:
            return self.created_threads[tid]

        return None

    def create_thread_subject(self, tid, time_micros, source):
        ''' Create a thread subject, add it to the created list, and return it
        '''
        record = {}
        subject = {}
        subject["properties"] = {}

        subject["startTimestampMicros"] = time_micros
        subject["type"] = "SUBJECT_THREAD"
        # TODO very much incomplete
        record["CDMVersion"] = self.CDMVersion
        record["datum"] = subject
        return record

    def get_user_id(self, uid):
        ''' Given a uid, did we create a Principal for that uid?
            If so, return the uid of the Principal, if not return None
        '''
        if uid in self.created_users:
            return self.created_users[uid]

        return None

    def create_user_principal(self, uid, source):
        ''' Create a user principal, add it to the created list, and return it
        '''
        record = {}
        principal = {}
        principal["uuid"] = self.create_uuid("uid", uid);
        principal["type"] = "PRINCIPAL_LOCAL"
        principal["userId"] = str(uid)
        if uid == 0:
            principal["username"] = "root"
        principal["groupIds"] = []
        principal["properties"] = {}

        # Save the uuid for this user
        self.created_users[uid] = principal["uuid"]

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = principal
        return record

    def get_file_object_id(self, file_key):
        ''' Given a file path or uuid, did we create an object for the it already?
            If found return the uuid of the object, if not return None
        '''
        return self.created_files.get(file_key)

    def create_unix_socket_object(self, file_uuid, source):
        ''' Infer the existence of a file object, add it to the created list, and return it.
            If version = None, look for an older version, and if found, add one and create a new Object
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
        fobject["uuid"] = self.create_uuid("uuid", uuid.UUID(file_uuid).int)


        fobject["version"] = 1

        # Save the uuid for this subject
        self.created_files[file_uuid] = fobject["uuid"]

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = fobject
        return record

    def create_unnamed_pipe_object(self, src_uuid, sink_uuid, source):
        ''' Infer the existence of a file object, add it to the created list, and return it.
            If version = None, look for an older version, and if found, add one and create a new Object
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}
        abstract_object["properties"]["sourceUuid"] = str(self.create_uuid("uuid", uuid.UUID(src_uuid).int))
        abstract_object["properties"]["sinkUuid"] = str(self.create_uuid("uuid", uuid.UUID(sink_uuid).int))

        fobject["baseObject"] = abstract_object
        fobject["sourceFileDescriptor"] = -1 # src_uuid
        fobject["sinkFileDescriptor"] = -1 # sink_uuid
        fobject["uuid"] = self.create_uuid("pipe", self.pipe_counter);
        self.pipe_counter += 1

        # Save the uuid for this subject
        self.created_files[src_uuid] = src_uuid
        self.created_files[sink_uuid] = sink_uuid

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = fobject
        return record

    def create_file_object(self, file_uuid, source, is_dir = False):
        ''' Infer the existence of a file object, add it to the created list, and return it.
            If version = None, look for an older version, and if found, add one and create a new Object
        '''

        record = {}
        fobject = {}
        abstract_object = {}
#         abstract_object["epoch"] = int
#         abstract_object["permission"] = SHORT
        abstract_object["properties"] = {}

        fobject["baseObject"] = abstract_object
        if is_dir:
            fobject["type"] = "FILE_OBJECT_DIR" # TODO: smarter file type
        else:
            fobject["type"] = "FILE_OBJECT_FILE" # TODO: smarter file type
#         fobject["localPrincipal"] = uuid
#         fobject["size"] = int
#         fobject["fileDescriptor"] = int
#         fobject["peInfo"] = string
#         fobject["hashes"] = array of hashes
        fobject["uuid"] = self.create_uuid("uuid", uuid.UUID(file_uuid).int)


        fobject["version"] = 1

        # Save the uuid for this subject
        self.created_files[file_uuid] = fobject["uuid"]

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = fobject
        return record

    def create_netflow_object(self, destHost, destPort, socket_uuid, source):
        ''' Infer the existence of a netflow object from a connection event with a addr and port key
            We always create a new netflow, so no need to look for an old uuid
            For now, we don't have the local host or local port, so we use "localhost" and -1
        '''

        record = {}
        nobject = {}
        abstract_object = {}
        abstract_object["properties"] = {}

        nobject["baseObject"] = abstract_object
        nobject["properties"] = {}
        nobject["localAddress"] = "localhost" # We don't know
        nobject["localPort"] = -1 # We don't know
        nobject["remoteAddress"] = destHost
        nobject["remotePort"] = destPort

        # Generate a uuid for this subject
        uniq = self.create_uuid("uuid", uuid.UUID(socket_uuid).int)
        self.netflow_counter += 1
        nobject["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["source"] = source
        record["datum"] = nobject

        self.created_files[socket_uuid] = nobject["uuid"]
        return record
