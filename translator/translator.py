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

    # Event counter, used for unique ids
    eventCounter = 0
    
    # If true, create a File object for any event with a path
    createFileObjects = True
    # If true, create new versions of the File object for every write event, if False, we'll only create one File subject
    createFileVersions = True
    
    # If true, create NetflowObject objects for each event with an address:port
    # Since we don't have the source host and source port, use defaults of localhost:-1
    createNetflowObjects = True

    CDMVersion = None
    
    instance_generator = None
    
    def __init__(self, schema, version):
        self.schema = schema
        self.CDMVersion = version
        self.instance_generator = InstanceGenerator(version)
        self.logger = logging.getLogger("tc")
        
    def reset(self):
        ''' Reset the translators counters and data structures.
            Use if you're parsing a new trace '''
        self.eventCounter = 0
        
        self.instance_generator.reset()        
        
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
        ppid = cadets_record.get("ppid", -1);
        cadets_proc_uuid = cadets_record.get("subjuuid", cadets_record["pid"]);

        proc_uuid = self.instance_generator.get_process_subject_id(pid, cadets_proc_uuid, cadets_record["exec"])
        if proc_uuid == None:
            self.logger.debug("Creating new Process Subject for {p}".format(p=pid))
            # We don't know the time when this process was created, so we'll leave it blank.
            # Could use time_micros as an upper bound, but we'd need to specify

            if "exec" in cadets_record:
                process_record = self.instance_generator.create_process_subject(pid, cadets_proc_uuid, ppid, None, self.get_source(), cadets_record["exec"])
            else:
                process_record = self.instance_generator.create_process_subject(pid, cadets_proc_uuid, ppid, None, self.get_source(), "")
            process = process_record["datum"]
            proc_uuid = process["uuid"]
            
            # Add some additional properties including executable name and command line args
            if "exec" in cadets_record:
                process["properties"]["exec"] = str(cadets_record["exec"])
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
            object_records = self.create_subjects(event, cadets_record)
            if object_records != None:
                for objr in object_records:
                    datums.append(objr)
            
            # Add an edge from the event to the subject that generated it
            self.logger.debug("Creating edge from Event {e} to Subject {s}".format(s=pid, e=event_type))    
            edge1 = self.create_edge(event["uuid"], proc_uuid, event["timestampMicros"], "EDGE_EVENT_ISGENERATEDBY_SUBJECT")
            datums.append(edge1)

        if "fork" in call: # link forked processes
            new_pid = cadets_record.get("new_pid", cadets_record.get("retval"));
            new_proc_uuid = cadets_record.get("ret_objuuid1", new_pid);

            cproc_uuid = self.instance_generator.get_process_subject_id(new_pid, new_proc_uuid, cadets_record["exec"])
            if cproc_uuid == None :
                proc_record = self.instance_generator.create_process_subject(new_pid, new_proc_uuid, cadets_record["pid"], None, self.get_source(), cadets_record["exec"])
                proc_record["datum"]["properties"]["exec"] = str(cadets_record["exec"])
                cproc_uuid = proc_record["datum"]["uuid"]
                datums.append(proc_record)
            self.logger.debug("Creating edge from Process {s} to parent process {p}".format(s=cproc_uuid, p=proc_uuid))
            fork_edge = self.create_edge(cproc_uuid, proc_uuid, time_micros, "EDGE_SUBJECT_HASPARENT_SUBJECT")
            datums.append(fork_edge)

        if "exec" in call: # link exec events to the file executed
            exec_path = cadets_record.get("new_exec", cadets_record.get("upath1"));
            cadets_proc_uuid = cadets_record.get("subjuuid", cadets_record["pid"]);

            short_name = exec_path
            if exec_path != None and exec_path.rfind("/") != -1:
                short_name = short_name[exec_path.rfind("/")+1:]
            cproc_uuid = self.instance_generator.get_process_subject_id(pid, cadets_proc_uuid, short_name)
            if cproc_uuid == None :
                proc_record = self.instance_generator.create_process_subject(pid, cadets_proc_uuid, ppid, None, self.get_source(), short_name)
                proc_record["datum"]["properties"]["exec"] = str(short_name);
                cproc_uuid = proc_record["datum"]["uuid"]
                datums.append(proc_record)
            self.logger.debug("Creating edge from File {s} to Event {p}".format(s=exec_path, p=event["uuid"]))
            if "arg_objuuid1" in cadets_record:
                file_uuid = self.instance_generator.get_file_object_id(cadets_record["arg_objuuid1"])
            else:
                file_uuid = self.instance_generator.get_file_object_id(exec_path)
            if file_uuid == None:
                file_record = self.instance_generator.create_file_object(cadets_record.get("arg_objuuid1"), exec_path, self.get_source(), None);
                datums.append(file_record)
                file_uuid = file_record["datum"]["uuid"]
            self.logger.debug("Creating edge from File {s} to Event {p}".format(s=exec_path, p=event["uuid"]))
            exec_file_edge = self.create_edge(file_uuid, event["uuid"], time_micros, "EDGE_FILE_AFFECTS_EVENT")
            self.logger.debug("Creating edge from Process {s} to parent process {p}".format(s=cproc_uuid, p=proc_uuid))
            exec_edge = self.create_edge(cproc_uuid, proc_uuid, time_micros, "EDGE_SUBJECT_HASPARENT_SUBJECT")
            datums.append(exec_file_edge)
            datums.append(exec_edge)

            # Add a HASLOCALPRINCIPAL edge from the process to the user
            if user_uuid != None:
                self.logger.debug("Creating edge from Subject {s} to Principal {u}".format(s=pid, u=uid))
                edge2 = self.create_edge(proc_uuid, user_uuid, time_micros, "EDGE_SUBJECT_HASLOCALPRINCIPAL")
                datums.append(edge2)

        return datums
    
    def translate_call(self, provider, module, call, probe, cadets_record):
        ''' Translate a system or function call event '''
        
        record = {}
        record["CDMVersion"] = self.CDMVersion
        old_record = {}
        old_record["CDMVersion"] = self.CDMVersion
        event = {}
        event["properties"] = {}

        uuid = self.instance_generator.create_uuid("event", self.eventCounter)
                
        event["uuid"] = uuid
        if provider == "syscall":
            event["type"] = self.convert_syscall_event_type(call)
        elif provider == "audit":
            event["type"] = self.convert_audit_event_type(call)
        else:
            event["type"] = "EVENT_APP_UNKNOWN"
            
        event["threadId"] = cadets_record["tid"]
        event["timestampMicros"] = cadets_record["time"] / 1000; # ns to micro
        
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
        elif "upath1" in cadets_record:
            event["properties"]["path"] = cadets_record["upath1"]
        
        record["datum"] = event
        record["CDMVersion"] = self.CDMVersion
        
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
                'exit' : 'EVENT_EXIT',
                'fork' : 'EVENT_FORK',
                'ftruncate' : 'EVENT_TRUNCATE',
                'kill' : 'EVENT_SIGNAL',
                'link' : 'EVENT_LINK',
                'linkat' : 'EVENT_LINK',
                'mmap' : 'EVENT_MMAP',
                'mprotect' : 'EVENT_MPROTECT',
                'open' : 'EVENT_OPEN',
                'openat' : 'EVENT_OPEN',
                'pread' : 'EVENT_READ',
                'preadv' : 'EVENT_READ',
                'pwrite' : 'EVENT_WRITE',
                'read' : 'EVENT_READ',
                'readv' : 'EVENT_READ',
                'recvfrom' : 'EVENT_RECVFROM',
                'recvmsg' : 'EVENT_RECVMSG',
                'rename' : 'EVENT_RENAME',
                'rfork' : 'EVENT_FORK',
                'sendmsg' : 'EVENT_SENDMSG',
                'sendto' : 'EVENT_SENDTO',
                'truncate' : 'EVENT_TRUNCATE',
                'unlink' : 'EVENT_UNLINK',
                'unlinkat' : 'EVENT_UNLINKAT',
                'vfork' : 'EVENT_FORK',
                'wait' : 'EVENT_WAIT',
                'waitid' : 'EVENT_WAIT',
                'wait3' : 'EVENT_WAIT',
                'wait4' : 'EVENT_WAIT',
                'wait6' : 'EVENT_WAIT',
                'waitpid' : 'EVENT_WAIT',
                'write' : 'EVENT_WRITE',
                'writev' : 'EVENT_WRITE'
        }.get(call, 'EVENT_OS_UNKNOWN')

    def convert_audit_event_type(self, call):
        ''' Convert the call to one of the CDM EVENT types, since there are specific types defined for common syscalls
            Fallthrough default is EVENT_OS_UNKNOWN
        '''
        prefix_dict = {'aue_execve' : 'EVENT_EXECUTE',
                'aue_accept' : 'EVENT_ACCEPT',
                'aue_bind' : 'EVENT_BIND',
                'aue_close' : 'EVENT_CLOSE',
                'aue_connect' : 'EVENT_CONNECT',
                'aue_exit' : 'EVENT_EXIT',
                'aue_fork' : 'EVENT_FORK',
                'aue_vfork' : 'EVENT_FORK',
                'aue_rfork' : 'EVENT_FORK',
                'aue_linkat' : 'EVENT_LINK',
                'aue_link' : 'EVENT_LINK',
                'aue_unlinkat' : 'EVENT_UNLINKAT',
                'aue_unlink' : 'EVENT_UNLINK',
                'aue_mmap' : 'EVENT_MMAP',
                'aue_mprotect' : 'EVENT_MPROTECT',
                'aue_open' : 'EVENT_OPEN',
                'aue_read' : 'EVENT_READ',
                'aue_pread' : 'EVENT_READ',
                'aue_write' : 'EVENT_WRITE',
                'aue_pwrite' : 'EVENT_WRITE',
                'aue_rename' : 'EVENT_RENAME',
                'aue_sendto' : 'EVENT_SENDTO',
                'aue_sendmsg' : 'EVENT_SENDMSG',
                'aue_recvfrom' : 'EVENT_RECVFROM',
                'aue_recvmsg' : 'EVENT_RECVMSG',
                'aue_kill' : 'EVENT_SIGNAL',
                'aue_truncate' : 'EVENT_TRUNCATE',
                'aue_ftruncate' : 'EVENT_TRUNCATE',
                'aue_wait' : 'EVENT_WAIT'
        }
        for key in prefix_dict:
            if(call.startswith(key)):
                return prefix_dict.get(key)
        return 'EVENT_OS_UNKNOWN'
                
                    
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
        record["CDMVersion"] = self.CDMVersion
        return record
    
    def create_subjects(self, event, cadets_record):
        ''' Given a CDM event that we just created, generate Subject instances and the corresponding edges
            Currently, we create:
              a subject for any file that we discover via a "path" property
              Plus an edge from the event to the subject,  EDGE_EVENT_AFFECTS_FILE or EDGE_FILE_AFFECTS_EVENT

        '''
        newRecords = []
        if self.createFileObjects and ("path" in event["properties"] or "arg_objuuid1" in cadets_record):
            if "path" in event["properties"]:
                path = event["properties"]["path"]
            else:
                path = ""
            etype = event["type"]
            
            if "arg_objuuid1" in cadets_record:
                file_uuid = self.instance_generator.get_file_object_id(cadets_record["arg_objuuid1"]) 
            else:
                file_uuid = self.instance_generator.get_file_object_id(path) 
            if file_uuid != None:
                if self.createFileVersions and etype == "EVENT_OPEN":
                    # open event, create a new version of the file, with path info
                    if "arg_objuuid1" in cadets_record:
                        self.logger.debug("Creating version of file {f}".format(f=path))
                        if self.instance_generator.get_latest_file_version(cadets_record["arg_objuuid1"]) == None:
                            fileobj = self.instance_generator.create_file_object(cadets_record["arg_objuuid1"], path, self.get_source(), None)
                            newRecords.append(fileobj)
                        else:
                            fileobj = self.instance_generator.create_file_object(cadets_record["arg_objuuid1"], path, self.get_source(), -1)
                            newRecords.append(fileobj)

                if self.createFileVersions and etype == "EVENT_WRITE":
                    self.logger.debug("Creating new version of file {f}".format(f=path))
                    # Write event, create a new version of the file
                    if "arg_objuuid1" in cadets_record:
                        old_version = self.instance_generator.get_latest_file_version(cadets_record["arg_objuuid1"])
                        fileobj = self.instance_generator.create_file_object(cadets_record["arg_objuuid1"], path, self.get_source(), None)
                    else:
                        old_version = self.instance_generator.get_latest_file_version(path)
                        fileobj = self.instance_generator.create_file_object(None, path, self.get_source(), None)
                    self.logger.debug("File version from {ov} to {nv}".format(ov=old_version, nv=fileobj["datum"]["version"]))
                    newRecords.append(fileobj)
                    
                    # Add an EDGE_OBJECT_PREV_VERSION
                    if old_version != None:
                        self.logger.debug("Adding PREV_VERSION edge")
                        edge1 = self.create_edge(file_uuid, fileobj["datum"]["uuid"], event["timestampMicros"], "EDGE_OBJECT_PREV_VERSION")
                        newRecords.append(edge1)
            else:
                self.logger.debug("Creating first version of the file")
                fileobj = self.instance_generator.create_file_object(cadets_record.get("arg_objuuid1"), path, self.get_source(), None)
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

