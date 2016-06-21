'''
Generate instances of CDM Subjects, Principals, and Objects.
Store a map of the instances we've created with their uuids, so we can tell if we already created a Record
  for a specific value (and get the uuid we generated for that record)
'''

import logging
import random
import struct

from tc.schema.records import record_generator

class InstanceGenerator():

    # Processes that we created Process subjects for mapped to the uid of the Process Subject
    created_processes = {}
   
    # Threads that we created Subjects for mapped to the uid of the Thread subject
    created_threads = {}
    
    # Users that we created a Principal for mapped to the uid of the Principal
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
        
    def create_uuid(self, object_type, data):
        ''' Create a unique ID from an object type ("pid" | "uid" | "tid" | "event" | "file" | "netflow") and data value
               where the data value is the actual pid, tid, or userId value

            UUIDs are now 128 bits

            For now, we use the data as the lower 64 bits
            For "uid", we set the next byte to 0x0
            For "pid", we set the next byte to 0x1
            For "tid", we set the next byte to 0x2
            For events, 0x3
            for "file", 0x4, and we hash the file path using the simple hash() method and use the lower 32 bits
            for "netflow", 0x5 and we use the counter as data
            
            0    32   64       (for a pid, where data is the pid value)
            0000 0001 data data   
        '''
        uuid = 0
        if object_type == "uid":
            uuid = 0
        elif object_type == "pid":
            uuid = (1 << 64)
        elif object_type == "tid":
            uuid = (2 << 64)
        elif object_type == "event":
            uuid = (3 << 64)
        elif object_type == "file":
            uuid = (4 << 64)
            # may want to replace with a better hash method, this one isn't portable, but it's fine for this use
            data = hash(data) & 0xFFFFFFFFFFFFFFFF
        elif object_type == "netflow":
            uuid = (5 << 64)
        else:
            raise Exception("Unknown object type in create_uuid: "+object_type)

	uuid = uuid | data

	# Eventually use this
	uuidb = record_generator.Util.get_uuid_from_value(uuid)
		    
	return uuidb
        
    def get_process_subject_id(self, pid, execname):
        ''' Given a pid, did we create a subject for the pid previously?
            If so return the uid of the subject, if not return None
        '''
        pid_exec = str(pid) +"_"+ execname
        if self.created_processes.has_key(hash(pid_exec)):
            return self.created_processes[hash(pid_exec)]

        return None

    def create_process_subject(self, pid, ppid, time_micros, source, execname):
        ''' Infer the existence of a process subject, add it to the created list, and return the subject (dictionary) '''
        
        record = {}
        subject = {}
        subject["properties"] = {}
        
        subject["pid"] = pid
        subject["ppid"] = ppid

	# We don't really know the start time of the process, since this method is inferring the existance of a process by the fact that it performed an action.
	# In CDM10 the startTimestampMicros is optional, so we'll let the caller set the value to None, meaning we don't know
	if time_micros != None:
	    subject["startTimestampMicros"] = time_micros
        subject["source"] = source
        subject["type"] = "SUBJECT_PROCESS"
        
        # Generate a uuid for this subject
        pid_exec = str(pid) +"_"+ execname
        uniq = self.create_uuid("pid", hash(pid_exec))
        self.created_processes[hash(pid_exec)] = uniq
        subject["uuid"] = uniq
        
        record["datum"] = subject
        record["CDMVersion"] = self.CDMVersion
        return record
        
    def get_thread_subject_id(self, tid):
        ''' Given a tid, did we create a subject for tid?
            If so, return the uid of the subject, if not return None
        '''
        if self.created_threads.has_key(tid):
            return self.created_threads[tid]
        
        return None
    
    def create_thread_subject(self, tid, time_micros, source):
        ''' Create a thread subject, add it to the created list, and return the dict '''
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
        
        record["datum"] = subject
        record["CDMVersion"] = self.CDMVersion
        return record
    
    def get_user_id(self, uid):
        ''' Given a uid, did we create a Principal for that uid?
            If so, return the uid of the Principal, if not return None
        '''
        if self.created_users.has_key(uid):
            return self.created_users[uid]
        
        return None
    
    def create_user_principal(self, uid, source):
        ''' Create a user principal, add it to the created list, and return the dict '''
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
                
        record["datum"] = principal
        record["CDMVersion"] = self.CDMVersion
        return record
    
    def get_file_object_id(self, path, version=None):
        ''' Given a file path, did we create an object for the path previously?
            If version = None, return the latest version, else look for that specific version
            If found return the uuid of the object, if not return None
        '''
        if self.created_files.has_key(path):
            versions = self.created_files[path]
            if version != None:
                if versions.has_key(version):
                    return versions[version]
            else:
                # In practice, there will only be one version here, since for now we only need to store the latest version
                mversion = max(versions)
                return versions[mversion]
        
        return None
    
    def get_latest_file_version(self, path):
        ''' Get the latest version of a file that we created an Object for.
            Currently, we only store the latest version
        '''
        if self.created_files.has_key(path):
            versions = self.created_files[path]
            return max(versions)
        return None
    
    def create_file_object(self, path, source, version=None):
        ''' Infer the existence of a file object, add it to the created list, and return the object (dictionary) 
            If version = None, look for an older version, and if found, add one and create a new Object 
        '''
        
        record = {}
        fobject = {}
        abstract_object = {}
        abstract_object["source"] = source
        abstract_object["properties"] = {}
        
        fobject["baseObject"] = abstract_object
        fobject["properties"] = {}
        fobject["url"] = str(path)
        fobject["isPipe"] = False 
        
        if version == None:
            # Look for an older version
            old_version = self.get_latest_file_version(path)
            
            if old_version == None:
                # Version is 1 then
                version = 1
            else:
                version = int(old_version) + 1
                
        fobject["version"] = version
        
        # Generate a uuid for this subject
        uniq = self.create_uuid("file", path)
        if self.created_files.has_key(path):
            versions = self.created_files[path]
            # we really only need to store the latest version for the moment
            # if we ever need to refer to older versions, remove this
            versions.clear()
            
            versions[version] = uniq
        else:
            versions = {}
            versions[version] = uniq
            self.created_files[path] = versions
        
        fobject["uuid"] = uniq
        
        record["datum"] = fobject
        record["CDMVersion"] = self.CDMVersion
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
        uniq = self.create_uuid("netflow", self.netflow_counter)
        self.netflow_counter += 1        
        nobject["uuid"] = uniq
        
        record["datum"] = nobject
        record["CDMVersion"] = self.CDMVersion
        return record
