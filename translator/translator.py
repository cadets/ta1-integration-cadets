'''
CADETS JSON record format to TC CDM format translator
'''

import logging
from instance_generator import InstanceGenerator

# These are the json keys in the CADETS record that we handle specifically in the translator.
# Any other keys not in this list, we'll add directly to the properties section of the Event
cdm_keys = ["event", "time", "pid", "ppid", "tid", "uid", "exec", "args"]

class CDMTranslator(object):
    
    # True: Raise an exception if we can't translate a record, False: just log it
    exceptionOnError = True

    # Event counter, used for unique ids and entry/return matching lookahead
    eventCounter = 0
    
    # Match entry events with return events and generate a single Event that combines the data in both
    # If false, instead we'll generate two separate events, one for the entry and one for the return
    matchEntryReturn = True
    # If we're matching, and we haven't found a return event in the next N events, just emit the entry by itself
    matchReturnLookahead = 5
    # Structure to store the entry events we're waiting for the returns for
    entryEvents = {}    # Key is the event type (<dtrace provider>:<module>:<function>:<probe name>) for the return event that we're waiting for
                        # Value is the entry event
                        
    # Store the lookahead left for each entry event we're tracking
    entryLookahead = {} # Key is the event type, value is the event count when we give up (eventCounter + matchReturnLookahead)
            
    # If true, create a File object for any event with a path
    createFileObjects = True
    # If true, create new versions of the File object for every write event, if False, we'll only create one File subject
    createFileVersions = True
    
    # If true, create NetflowObject objects for each event with an address:port
    # Since we don't have the source host and source port, use defaults of localhost:-1
    createNetflowObjects = True
    
    instance_generator = InstanceGenerator()
    
    def __init__(self, schema):
        self.schema = schema
        self.logger = logging.getLogger("tc")
        
    def reset(self):
        ''' Reset the translators counters and data structures.
            Use if you're parsing a new trace '''
        self.eventCounter = 0
        
        self.instance_generator.reset()        
        self.entryEvents.clear()
        self.entryLookahead.clear()
        
    def get_source(self):
        ''' Get the InstrumentationSource, for now this is hardcoded to SOURCE_FREEBSD_DTRACE_CADETS '''
        return "SOURCE_FREEBSD_DTRACE_CADETS"
    
    def handle_error(self, msg):
        if self.exceptionOnError:
            raise msg
        else:
            self.logger.error(msg)

    def translate_record(self, cadets_record):
        ''' Generate a CDM record from the passed in JSON CADETS record '''
        
        # List of CDM vertices or edges that we created from this record
        datums = []
        
        # nanos to micros
        time_micros = cadets_record["time"] / 1000
        
        # Create a new user if necessary
        uid = cadets_record["uid"]
        user_uuid = self.instance_generator.get_user_id(uid)
        if user_uuid == None:
            self.logger.debug("Creating new User Principal for {u}".format(u=uid))
            principal = self.instance_generator.create_user_principal(uid, self.get_source())
            user_uuid = principal["datum"]["uuid"]
            datums.append(principal)
            
        # Create a new Process subject if necessary
        pid = cadets_record["pid"]
        ppid = -1 # TODO: Default value
        if "ppid" in cadets_record:
            ppid = cadets_record["ppid"]
            
        proc_uuid = self.instance_generator.get_process_subject_id(pid)
        if proc_uuid == None:
            self.logger.debug("Creating new Process Subject for {p}".format(p=pid))
            process_record = self.instance_generator.create_process_subject(pid, ppid, time_micros, self.get_source())
            process = process_record["datum"]
            proc_uuid = process["uuid"]
            
            # Add some additional properties including executable name and command line args
            if "exec" in cadets_record:
                process["properties"]["exec"] = cadets_record["exec"]
            if "args" in cadets_record:
                process["cmdLine"] = cadets_record["args"]
                            
            datums.append(process_record)
            
            # Add a HASLOCALPRINCIPAL edge from the process to the user
            if user_uuid != None:
                self.logger.debug("Creating edge from Subject {s} to Principal {u}".format(s=pid, u=uid))
                edge2 = self.create_edge(proc_uuid, user_uuid, time_micros, "EDGE_SUBJECT_HASLOCALPRINCIPAL")
                datums.append(edge2)
            
        # Create a new Thread subject if necessary
        
        # TODO:  For now, we'll skip creating the Thread
        if False:
            tid = cadets_record["tid"]
            thread_uuid = self.instance_generator.get_thread_subject_id(tid)
            if thread_uuid == None:
                self.logger.debug("Creating new Thread Subject for {t}".format(t=tid))
                thread = self.instance_generator.create_thread_subject(tid, time_micros, self.get_source())
                thread_uuid = thread["datum"]["uuid"]
                datums.append(thread)
        
        # dispatch based on type
        event_type = cadets_record["event"]
        event_components = event_type.split(":")
        if len(event_components) < 4:            
            self.handle_error("Expecting 4 elements in the event type: provider:module:function:probe. Got: "+event_type)
                
        provider = event_components[0]
        module = event_components[1]
        call = event_components[2]
        probe = event_components[3]
                
        # Create the Event
        self.logger.debug("Creating Event from {e} ".format(e=event_type))
        event_record = self.translate_call(provider, module, call, probe, cadets_record)
        
        event = None
        if event_record != None:
            event = event_record["datum"]
            datums.append(event_record)
            object_records = self.create_subjects(event)
            if object_records != None:
                for objr in object_records:
                    datums.append(objr)
            
            # Add an edge from the event to the subject that generated it
            self.logger.debug("Creating edge from Event {e} to Subject {s}".format(s=pid, e=event_type))    
            edge1 = self.create_edge(event["uuid"], proc_uuid, event["timestampMicros"], "EDGE_EVENT_ISGENERATEDBY_SUBJECT")
            datums.append(edge1)
        
        return datums
    
    def handle_entry_match(self, fastForward=False):
        ''' If we are matching entry and return events, combining them into one, update here '''
        datums = []
        
        cur_counter = self.eventCounter
        if fastForward:
            # move ahead to the lookahead, so we generate events for everything we're waiting for
            # this is used at the end, when we're done with cadets records and we want to finish and generate events for
            # anything we're still looking for a return for
            cur_counter = self.eventCounter + self.matchReturnLookahead + 1
            
        if self.matchEntryReturn:
            # Give up on any returns we are waiting that are now past the event lookahead
            giveup = []
            for rt in self.entryLookahead:
                rtCounter = self.entryLookahead[rt]
                if rtCounter <= cur_counter:
                    # Add the entry event
                    try:
                        entry_event_record = self.entryEvents[rt]
                        entry_event = entry_event_record["datum"]
                        
                        self.logger.debug("Gave up waiting for return for entry event {e}, creating event".format
                                          (e=entry_event["type"]))
                                  
                        creator_pid = entry_event_record["tempPid"]
                        del entry_event_record["tempPid"]
                        entry_proc_uuid = self.instance_generator.get_process_subject_id(creator_pid)
                        datums.append(entry_event_record)
                        
                        object_records = self.create_subjects(entry_event)
                        if object_records != None:
                            for objr in object_records:
                                datums.append(objr)

                        # Add an edge from the event to the subject that generated it
                        self.logger.debug("Creating edge from Event {e} to Subject {s}".format
                                          (s=creator_pid, e=entry_event["type"]))    
                        edge2 = self.create_edge(entry_event["uuid"], entry_proc_uuid, entry_event["timestampMicros"], 
                                                 "EDGE_EVENT_ISGENERATEDBY_SUBJECT")
                        datums.append(edge2)
                        giveup.append(rt)
                    except KeyError:
                        pass
            
            for rt in giveup:
                del self.entryLookahead[rt]
                del self.entryEvents[rt]
                
        return datums
    
    def translate_call(self, provider, module, call, probe, cadets_record):
        ''' Translate a system or function call event '''
        
        record = {}
        old_record = {}
        event = {}
        event["properties"] = {}

        uuid = self.instance_generator.create_uuid("event", self.eventCounter)
                
        event["uuid"] = uuid
        if provider == "syscall":
            event["type"] = self.convert_syscall_event_type(call)
        else:
            event["type"] = "EVENT_APP_UNKNOWN"
            
        event["threadId"] = cadets_record["tid"]
        event["timestampMicros"] = cadets_record["time"]
        
        # Use the event counter as the seq number
        # This assumes we're processing events in order
        event["sequence"] = self.eventCounter
        self.eventCounter += 1

        event["source"] = self.get_source()

        event["properties"]["probe"] = probe
        if "args" in cadets_record:
            event["properties"]["args"] = cadets_record["args"]        
        event["properties"]["call"] = call
        event["properties"]["module"] = module
        event["properties"]["provider"] = provider
        
        for key in cadets_record:
            if not key in cdm_keys: # we already handled the standard CDM keys
                event["properties"][str(key)] = str(cadets_record[key]) 
                # for other keys, (path, fd, address, port, query, request)
                # Store the value in properties
            
        if "path" in cadets_record:
            event["properties"]["path"] = cadets_record["path"]
        
        record["datum"] = event
        
        if self.matchEntryReturn:
            returnType = "{provider}:{module}:{call}:return".format(provider=provider, module=module, call=call)
            if probe == "entry":
                # Don't generate an event for the entry, wait for the return and combine the two
                # Record the event type we're waiting for
                
                # Store the pid of the process that generated the event temporarily
                record["tempPid"] = cadets_record["pid"] # Remove this when we finalize the event
                
                returnNone = True
                if returnType in self.entryEvents: # this return type is already being waited for, so stop waiting for the previous one
                    self.logger.debug("Found new entry probe instead of return we were waiting for: {provider}:{module}:{call}".format(provider=provider, module=module, call=call))
                    entryEventRecord = self.entryEvents[returnType]
                    entryEvent = entryEventRecord["datum"]
                    old_record["datum"] = entryEvent
                    returnNone = False

                self.entryEvents[returnType] = record
                # Give up looking after matchReturnLookahead more events
                self.entryLookahead[returnType] = self.eventCounter + self.matchReturnLookahead
            
                self.logger.debug("Waiting for return probe for entry event: {rt}, giving up in {ec} events"
                                  .format(rt=returnType, ec=self.matchReturnLookahead))
                if returnNone:
                    return None
                else:
                    return old_record
            elif probe == "return":
                # Are we waiting for this return?
                try:
                    if returnType in self.entryEvents:
                        self.logger.debug("Found return probe we were waiting for: {rt}".format(rt=returnType))
                        entryEventRecord = self.entryEvents[returnType]
                        
                        # Combine the events
                        entryEvent = entryEventRecord["datum"]
                        entryEvent["properties"]["probe"] = "entry:return"
                    
                        # Event timestamp is the call time, the return time will be a property
                        entryEvent["properties"]["returnTimestampMicros"] = str(event["timestampMicros"])
                        if "args" in event["properties"]:
                            entryEvent["properties"]["returnArgs"] = event["properties"]["args"]
                        record["datum"] = entryEvent
                    
                        self.logger.debug("New record: "+str(record))
                        del self.entryEvents[returnType]
                        del self.entryLookahead[returnType]
                except KeyError as ex:
                    self.logger.warn("KeyError: "+str(ex))
                    pass
                    
        return record
    
    def convert_syscall_event_type(self, call):
        ''' Convert the call to one of the CDM EVENT types, since there are specific types defined for common syscalls
            Fallthrough default is EVENT_OS_UNKNOWN
        '''
        return {'execve' : 'EVENT_EXECUTE',
                'accept' : 'EVENT_ACCEPT',
                'accept4' : 'EVENT_ACCEPT',
                'bind' : 'EVENT_BIND',
                'close' : 'EVENT_CLOSE',
                'connect' : 'EVENT_CONNECT',
                'fork' : 'EVENT_FORK',
                'link' : 'EVENT_LINK',
                'linkat' : 'EVENT_LINK',
                'unlink' : 'EVENT_UNLINK',
                'unlinkat' : 'EVENT_UNLINKAT',
                'mmap' : 'EVENT_MMAP',
                'mprotect' : 'EVENT_MPROTECT',
                'open' : 'EVENT_OPEN',
                'openat' : 'EVENT_OPEN',
                'read' : 'EVENT_READ',
                'readv' : 'EVENT_READ',
                'pread' : 'EVENT_READ',
                'preadv' : 'EVENT_READ',
                'write' : 'EVENT_WRITE',
                'pwrite' : 'EVENT_WRITE',
                'writev' : 'EVENT_WRITE',
                'kill' : 'EVENT_SIGNAL',
                'truncate' : 'EVENT_TRUNCATE',
                'ftruncate' : 'EVENT_TRUNCATE',
                'wait' : 'EVENT_WAIT',
                'waitid' : 'EVENT_WAIT',
                'waitpid' : 'EVENT_WAIT',
                'wait3' : 'EVENT_WAIT',
                'wait4' : 'EVENT_WAIT',
                'wait6' : 'EVENT_WAIT'
        }.get(call, 'EVENT_OS_UNKNOWN')
                
                    
    def create_edge(self, fromUuid, toUuid, timestamp, edge_type):
        ''' Create a 'type' Edge from the fromUuid to the toUuid object" '''
        edge = {}
        
        edge["properties"] = {}
        edge["fromUuid"] = fromUuid
        edge["toUuid"] = toUuid
        edge["type"] = edge_type
        edge["timestamp"] = timestamp

        record = {}
        record["datum"] = edge
        return record
    
    def create_subjects(self, event):
        ''' Given a CDM event that we just created, generate Subject instances and the corresponding edges
            Currently, we create:
              a subject for any file that we discover via a "path" property
              Plus an edge from the event to the subject,  EDGE_EVENT_AFFECTS_FILE or EDGE_FILE_AFFECTS_EVENT

        '''
        newRecords = []
        if self.createFileObjects and "path" in event["properties"]:
            path = event["properties"]["path"]
            etype = event["type"]
            
            file_uuid = self.instance_generator.get_file_object_id(path) 
            if file_uuid != None:
                if self.createFileVersions and etype == "EVENT_WRITE":
                    self.logger.debug("Creating new version of file {f}".format(f=path))
                    # Write event, create a new version of the file
                    old_version = self.instance_generator.get_latest_file_version(path)
                    fileobj = self.instance_generator.create_file_object(path, self.get_source(), None)
                    self.logger.debug("File version from {ov} to {nv}".format(ov=old_version, nv=fileobj["datum"]["version"]))
                    newRecords.append(fileobj)
                    
                    # Add an EDGE_OBJECT_PREV_VERSION
                    if old_version != None:
                        self.logger.debug("Adding PREV_VERSION edge")
                        edge1 = self.create_edge(file_uuid, fileobj["datum"]["uuid"], event["timestampMicros"], "EDGE_OBJECT_PREV_VERSION")
                        newRecords.append(edge1)
            else:
                self.logger.debug("Creating first version of the file")
                fileobj = self.instance_generator.create_file_object(path, self.get_source(), 1) # first version of this file
                file_uuid = fileobj["datum"]["uuid"]
                newRecords.append(fileobj)
            
            if etype == "EVENT_WRITE":
                # Writes create an edge from the event to the file object
                self.logger.debug("Creating EVENT_AFFECTS_FILE edge for a file write")
                edge2 = self.create_edge(event["uuid"], file_uuid, event["timestampMicros"], "EDGE_EVENT_AFFECTS_FILE")
                newRecords.append(edge2)
            else:
                # anything else (read/open) create an edge from the file object to the event
                self.logger.debug("Creating FILE_AFFECTS_EVENT for the read or open")
                edge2 = self.create_edge(file_uuid, event["uuid"], event["timestampMicros"], "EDGE_FILE_AFFECTS_EVENT")
                newRecords.append(edge2)
            
        # NetFlows
        if self.createNetflowObjects and "address" in event["properties"] and "port" in event["properties"]:
            destAddr = event["properties"]["address"]
            destPort = int(event["properties"]["port"])
            
            self.logger.debug("Creating a NetflowObject from {h}:{p}".format(h=destAddr, p=destPort))
            nf_obj = self.instance_generator.create_netflow_object(destAddr, destPort, self.get_source())
            nf_uuid = nf_obj["datum"]["uuid"]
            newRecords.append(nf_obj)
            
            # Add an EDGE_EVENT_AFFECTS_NETFLOW
            # TODO: which direction should this edge go? event -> netflow or netflow -> event
            self.logger.debug("Creating a EVENT_AFFECTS_NETFLOW edge")
            edge3 = self.create_edge(event["uuid"], nf_uuid, event["timestampMicros"], "EDGE_EVENT_AFFECTS_NETFLOW")
            newRecords.append(edge3)            
        
        return newRecords