'''
Generate instances of CDM Subjects, Principals, and Objects.  
Store a map of the instances we've created with their uuids, so we can tell if
we already created a Record for a specific value (and get the uuid we generated
for that record)
'''

import logging
import uuid

from tc.schema.records import record_generator

UID_NAMESPACE = uuid.UUID('6ba7b813-9dad-11d1-80b4-00c04fd430c8')

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

    CDMVersion = None

    def __init__(self, version):
        self.CDMVersion = version
        self.logger = logging.getLogger("tc")

    def reset(self):
        self.created_processes.clear()
        self.created_threads.clear()
        self.created_users.clear()
        self.created_files.clear()

    def create_uuid(self, object_type, data):
        ''' Create a unique ID from an object type ("pid" | "uid" | "tid" | "event" | "file" | "netflow") and data value
               where the data value is the actual pid, tid, or userId value

            UUIDs are now 128 bits

            For "uid", generate an RFC4122 v4 UUID
            For "event", generate an RFC4122 v5 UUID
            for "netflow", generate an RFC4122 v4 UUID
            for "uuid", we use given uuid (on pid, tid, file)
        '''
        id = 0
        if object_type == "uid":
            id = uuid.uuid5(UID_NAMESPACE, str(data)).int
        elif object_type == "event":
            id = uuid.uuid4().int
        # XXX: Use socket UUIDs eventually
        elif object_type == "netflow":
            id = uuid.uuid4().int
        elif object_type == "uuid":
            id = data
        else:
            raise Exception("Unknown object type in create_uuid: "+object_type)

        # Eventually use this
        return record_generator.Util.get_uuid_from_value(id)

    def get_process_subject_id(self, pid, puuid):
        ''' Given a pid, did we create a subject for the pid previously?
            If so return the uid of the subject, if not return None
        '''
        if self.created_processes.has_key(puuid):
            return self.created_processes[puuid]

        return None

    def create_process_subject(self, pid, puuid, ppid, time_micros, source):
        ''' Create a process subject, add it to the created list, and return it
        '''

        record = {}
        subject = {}
        subject["properties"] = {}

        subject["pid"] = pid
        subject["ppid"] = ppid

        # We don't really know the start time of the process, since this method
        # is inferring the existance of a process by the fact that it performed
        # an action.  startTimestampMicros is optional, so we'll let the caller
        # set the value to None, meaning we don't know
        if time_micros != None:
            subject["startTimestampMicros"] = time_micros
        subject["source"] = source
        subject["type"] = "SUBJECT_PROCESS"

        # Generate a uuid for this subject
        if puuid == str(pid):
            uniq = self.create_uuid("pid", puuid)
        else:
            uniq = self.create_uuid("uuid", uuid.UUID(puuid).int)
        self.created_processes[puuid] = uniq
        subject["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["datum"] = subject
        return record

    def get_thread_subject_id(self, tid):
        ''' Given a tid, did we create a subject for tid?
            If so, return the uid of the subject, if not return None
        '''
        if self.created_threads.has_key(tid):
            return self.created_threads[tid]

        return None

    def create_thread_subject(self, tid, time_micros, source):
        ''' Create a thread subject, add it to the created list, and return it
        '''
        record = {}
        subject = {}
        subject["properties"] = {}

        subject["startTimestampMicros"] = time_micros
        subject["source"] = source
        subject["type"] = "SUBJECT_THREAD"
        subject["pid"] = tid # TODO: Do we put the tid here in the pid field?
        subject["ppid"] = -1 # TODO: This should be optional

        # Generate a uuid for this subject
        uniq = self.create_uuid("tid", tid)
        self.created_threads[tid] = uniq
        subject["uuid"] = uniq

        # TODO: tid can be a property
        # subject["properties"]["tid"] = tid

        record["CDMVersion"] = self.CDMVersion
        record["datum"] = subject
        return record

    def get_user_id(self, uid):
        ''' Given a uid, did we create a Principal for that uid?
            If so, return the uid of the Principal, if not return None
        '''
        if self.created_users.has_key(uid):
            return self.created_users[uid]

        return None

    def create_user_principal(self, uid, source):
        ''' Create a user principal, add it to the created list, and return it
        '''
        record = {}
        principal = {}
        principal["properties"] = {}
        principal["userId"] = str(uid)
        principal["source"] = source
        principal["groupIds"] = []
        principal["type"] = "PRINCIPAL_LOCAL"

        # Generate a uuid for this user
        uniq = self.create_uuid("uid", uid)
        self.created_users[uid] = uniq
        principal["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["datum"] = principal
        return record

    def get_file_object_id(self, file_key, version=None):
        ''' Given a file path or uuid, did we create an object for the it already?
            If version = None, return the latest version, else look for that specific version
            If found return the uuid of the object, if not return None
        '''
        if self.created_files.has_key(file_key):
            versions = self.created_files[file_key]
            if version != None:
                if versions.has_key(version):
                    return versions[version]
            else:
                # In practice, there will only be one version here, since for now we only need to store the latest version
                mversion = max(versions)
                return versions[mversion]

        return None

    def get_latest_file_version(self, file_key):
        ''' Get the latest version of a file that we created an Object for.
            Currently, we only store the latest version
        '''
        if self.created_files.has_key(file_key):
            versions = self.created_files[file_key]
            return max(versions)
        return None

    def create_file_object(self, id, path, source, version=None):
        ''' Infer the existence of a file object, add it to the created list, and return it.
            If version = None, look for an older version, and if found, add one and create a new Object
        '''

        if id != None:
            file_key = id
        else:
            file_key = path
        record = {}
        fobject = {}
        abstract_object = {}
        abstract_object["source"] = source
        abstract_object["properties"] = {}

        fobject["baseObject"] = abstract_object
        fobject["properties"] = {}
        fobject["url"] = str(path)
        fobject["isPipe"] = False

        if version is None:
            # Look for an older version
            old_version = self.get_latest_file_version(file_key)

            if old_version is None: # First version then
                version = 1
            else:
                version = int(old_version) + 1

        fobject["version"] = version

        # Generate a uuid for this subject
        uniq = self.create_uuid("uuid", uuid.UUID(id).int)

        if self.created_files.has_key(file_key):
            versions = self.created_files[file_key]
            max_version = self.get_latest_file_version(file_key)
            if version > max_version:
                max_version = version
            versions.clear() # Only keep the most recent
            versions[max_version] = uniq
        else:
            versions = {}
            versions[version] = uniq
            self.created_files[file_key] = versions

        fobject["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["datum"] = fobject
        return record

    def create_netflow_object(self, destHost, destPort, source):
        ''' Infer the existence of a netflow object from a connection event with a addr and port key
            We always create a new netflow, so no need to look for an old uuid
            For now, we don't have the local host or local port, so we use "localhost" and -1
        '''

        record = {}
        nobject = {}
        abstract_object = {}
        abstract_object["source"] = source
        abstract_object["properties"] = {}

        nobject["baseObject"] = abstract_object
        nobject["properties"] = {}
        nobject["srcAddress"] = "localhost" # We don't know
        nobject["srcPort"] = -1 # We don't know
        nobject["destAddress"] = destHost
        nobject["destPort"] = int(destPort)

        # Generate a uuid for this subject
        uniq = self.create_uuid("netflow", 0)
        nobject["uuid"] = uniq

        record["CDMVersion"] = self.CDMVersion
        record["datum"] = nobject
        return record
