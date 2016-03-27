'''
CADETS JSON record format to TC CDM format translator
'''

import logging

class CDMTranslator(object):
    
    # Processes that we created Process subjects for mapped to the uid of the Process Subject
    created_processes = {}
   
    # Threads that we created Subjects for mapped to the uid of the Thread subject
    created_threads = {}
    
    # Users that we created a Principal for mapped to the uid of the Principal
    created_users = {}

    # True: Raise an exception if we can't translate a record, False: just log it
    exceptionOnError = True

    # Event counter for unique ids
    eventCounter = 0

    def __init__(self, schema):
        self.schema = schema
        self.logger = logging.getLogger("tc")
        
    def get_source(self):
        ''' Get the InstrumentationSource, for now this is hardcoded to SOURCE_FREEBSD_DTRACE_CADETS '''
        return "SOURCE_FREEBSD_DTRACE_CADETS"
        # return "SOURCE_FREEBSD_OPENBSM_TRACE"
    
    def create_uuid(self, object_type, data):
        ''' Create a unique ID from an object type and data value
            For now, we use the data as the lower 32 bits
            For "uid", we set the next byte to 0x0
            For "pid", we set the next byte to 0x1
            For "tid", we set the next byte to 0x2
            For events, 0x3
            0    16   32   48     (for a pid, where data is the pid value)
            0000 0001 data data   
        '''
        uuid = 0
        if object_type == "pid":
            uuid = (1 << 32)
        elif object_type == "tid":
            uuid = (2 << 32)
        elif object_type == "event":
            uuid = (3 << 32)
        uuid = uuid | data
        return uuid
        
    def get_process_subject_id(self, pid):
        ''' Given a pid, did we create a subject for the pid previously? 
            If som return the uid of the subject, if not reutrn None
        '''
        if self.created_processes.has_key(pid):
            return self.created_processes[pid]
        
        return None
    
    def create_process_subject(self, pid, time_micros, source):
        ''' Create a process subject, add it to the created list, and return the dict '''
        record = {}
        subject = {}
        subject["properties"] = {}
        
        subject["pid"] = pid
        subject["ppid"] = -1  # TODO: Default value?
        subject["startTimestampMicros"] = time_micros
        subject["source"] = source
        subject["type"] = "SUBJECT_PROCESS"
        
        # Generate a uuid for this subject
        uniq = self.create_uuid("pid", pid)
        self.created_processes[pid] = uniq
        subject["uuid"] = uniq
        
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
        principal["userId"] = uid
        principal["source"] = source
        principal["groupIds"] = []
        principal["type"] = "PRINCIPAL_LOCAL"
        
        # Generate a uuid for this user
        uniq = self.create_uuid("uid", uid)
        self.created_users[uid] = uniq
        principal["uuid"] = uniq
                
        record["datum"] = principal
        return record
    
    def handle_error(self, msg):
        if self.exceptionOnError:
            raise msg
        else:
            self.logger.error(msg)

    def translate_record(self, cadets_record):
        ''' Generate a CDM record from the passed in JSON CADETS record '''
        
        # List of CDM vertices or edges that we created from this record
        datums = []
        
        time_micros = cadets_record["time"]
        
        # Create a new user if necessary
        uid = cadets_record["uid"]
        user_uuid = self.get_user_id(uid)
        if user_uuid == None:
            self.logger.info("Creating new User Principal for {u}".format(u=uid))
            principal = self.create_user_principal(uid, self.get_source())
            user_uuid = principal["datum"]["uuid"]
            datums.append(principal)
            
        # Create a new Process subject if necessary
        pid = cadets_record["pid"]
        proc_uuid = self.get_process_subject_id(pid)
        if proc_uuid == None:
            self.logger.info("Creating new Process Subject for {p}".format(p=pid))
            process = self.create_process_subject(pid, time_micros, self.get_source())
            proc_uuid = process["datum"]["uuid"]
            datums.append(process)
            
        # Create a new Thread subject if necessary
        tid = cadets_record["tid"]
        thread_uuid = self.get_thread_subject_id(tid)
        if thread_uuid == None:
            self.logger.info("Creating new Thread Subject for {t}".format(t=tid))
            thread = self.create_thread_subject(tid, time_micros, self.get_source())
            thread_uuid = thread["datum"]["uuid"]
            datums.append(thread)
        
        # dispatch based on type
        event_type = cadets_record["event"]
        event_components = event_type.split(":")
        if len(event_components) < 4:            
            self.handle_error("Expecting 4 elements in the event type: provider:module:function:probe. Got: "+event_type)
                
        module = event_components[1]
        call = event_components[2]
        probe = event_components[3]
                
        if event_components[0] == "syscall":
            event1 = self.translate_syscall(module, call, probe, cadets_record)
            edge1 = self.create_edge(proc_uuid, event1["datum"])
            datums.append(event1)
            datums.append(edge1)
        else:
            event2 = self.translate_appcall(event_components[0], module, call, probe, cadets_record)
            edge2 = self.create_edge(proc_uuid, event2["datum"])
            datums.append(event2)
            datums.append(edge2)
                    
        return datums
    
    def translate_syscall(self, module, call, probe, cadets_record):
        ''' Translate a syscall event '''
        
        # for now, translate the probe value (entry / exit) as a property
        record = {}
        event = {}
        event["properties"] = {}

        uuid = self.create_uuid("event", self.eventCounter)
        self.eventCounter += 1
        
        event["uuid"] = uuid
        # TODO: Translate the event type, for now map everything to OS_UNKNOWN
        event["type"] = "EVENT_OS_UNKNOWN"
        event["threadId"] = cadets_record["tid"]
        event["timestampMicros"] = cadets_record["time"]
        event["sequence"] = 0 # TODO: Sequence numbers
        event["source"] = self.get_source()
        # TODO: arguments

        event["properties"]["probe"] = probe        
        
        record["datum"] = event
        return record
    
    def create_edge(self, proc_uuid, event):    
        edge = {}
        event_uuid = event["uuid"]
        timestamp = event["timestampMicros"]
        edge["properties"] = {}
        edge["fromUuid"] = proc_uuid
        edge["toUuid"] = event_uuid
        edge["type"] = "EDGE_EVENT_ISGENERATEDBY_SUBJECT"
        edge["timestamp"] = timestamp

        record = {}
        record["datum"] = edge
        return record