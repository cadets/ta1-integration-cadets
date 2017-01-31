'''
CADETS JSON record format to TC CDM format translator
'''

import logging
from uuid import UUID
from instance_generator import InstanceGenerator

# These are the json keys in the CADETS record that we handle specifically in
# the translator.  Any keys not in this list, we'll add directly to the
# properties section of the Event
cdm_keys = ["event", "time", "pid", "ppid", "tid", "uid", "exec", "args", "subjprocuuid", "subjthruuid", "errno"]
file_calls = ["EVENT_UNLINKAT", "EVENT_UNLINK", "EVENT_RENAME", "EVENT_MMAP", "EVENT_TRUNCATE", "EVENT_EXECUTE", "EVENT_OPEN", "EVENT_CLOSE", "EVENT_READ", "EVENT_WRITE", "aue_chown", "aue_lchown", "aue_fchown", "aue_chmod", "aue_lchmod", "aue_fchmod", "aue_fchmodat"] # TODO not complete list
no_uuids_calls = []
process_calls = ["EVENT_FORK", "EVENT_EXIT", "kill"]
network_calls = ["recvfrom", "recvmsg", "sendto", "sendmsg", "socketpair", "socket", "connect", "accept"]
uuid_keys = ["arg_objuuid1", "arg_objuuid2", "ret_objuuid1", "ret_objuuid2"]

class CDMTranslator(object):

    # True: Raise an exception if we can't translate a record
    # False: just log it
    exceptionOnError = True

    # Event counter, used for unique ids
    eventCounter = 0

    # If true, create a File object for any event with a path
    createFileObjects = True

    # If true, create NetflowObject objects for each event with an address:port
    # Since we don't have the source host and port, use defaults of localhost:-1
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

        # List of CDM vertices
        datums = []

        # nanos to micros
        time_micros = cadets_record["time"] / 1000

        # Create a new user if necessary
        uid = cadets_record["uid"]
        user_uuid = self.instance_generator.get_user_id(uid)
        if user_uuid is None:
            self.logger.debug("Creating new User Principal for {u}".format(u=uid))
            principal = self.instance_generator.create_user_principal(uid, self.get_source())
            user_uuid = principal["datum"]["uuid"]
            datums.append(principal)

        # Create a new Process subject if necessary
        pid = cadets_record["pid"]
        ppid = cadets_record.get("ppid", -1)
        cadets_proc_uuid = cadets_record.get("subjprocuuid", str(cadets_record["pid"]))

        proc_uuid = self.instance_generator.get_process_subject_id(pid, cadets_proc_uuid)
        if proc_uuid is None:
            self.logger.debug("Creating new Process Subject for {p}".format(p=pid))
            # We don't know the time when this process was created, so we'll leave it blank.
            # Could use time_micros as an upper bound, but we'd need to specify

            process_record = self.instance_generator.create_process_subject(pid, cadets_proc_uuid, ppid, None, self.get_source())
            process = process_record["datum"]
            proc_uuid = process["uuid"]

            datums.append(process_record)


        # Create a new Thread subject if necessary
        # TODO:  For now, we'll skip creating the Thread
        if False:
            tid = cadets_record["tid"]
            thread_uuid = self.instance_generator.get_thread_subject_id(tid)
            if thread_uuid is None:
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

        event["properties"]["subjprocuuid"] = str(UUID(cadets_record["subjprocuuid"]).hex)

        if "fork" in call: # link forked processes
            new_pid = cadets_record.get("retval")
            new_proc_uuid = cadets_record.get("ret_objuuid1", str(new_pid))

            cproc_uuid = self.instance_generator.get_process_subject_id(new_pid, new_proc_uuid)
            if cproc_uuid is None:
                proc_record = self.instance_generator.create_process_subject(new_pid, new_proc_uuid, cadets_record["pid"], None, self.get_source())
                cproc_uuid = proc_record["datum"]["uuid"]
                datums.append(proc_record)

        if "exec" in call: # link exec events to the file executed
            exec_path = cadets_record.get("upath1")
            file_uuid = self.instance_generator.get_file_object_id(cadets_record["arg_objuuid1"])
            if file_uuid is None:
                file_record = self.instance_generator.create_file_object(cadets_record.get("arg_objuuid1"), self.get_source())
                datums.append(file_record)

        return datums

    def translate_call(self, provider, module, call, probe, cadets_record):
        ''' Translate a system or function call event '''

        record = {}
        record["CDMVersion"] = self.CDMVersion
        event = {}
        event["properties"] = {}

        uuid = self.instance_generator.create_uuid("event", self.eventCounter)

        event["uuid"] = uuid
        if provider == "audit":
            event["type"] = self.convert_audit_event_type(call)
        else:
            event["type"] = "EVENT_APP_UNKNOWN"

        event["threadId"] = cadets_record["tid"]
        event["timestampMicros"] = int(cadets_record["time"] / 1000) # ns to micro

        # Use the event counter as the seq number
        # This assumes we're processing events in order
        event["sequence"] = self.eventCounter
        self.eventCounter += 1

        event["source"] = self.get_source()

        event["properties"]["call"] = call
        if provider != "audit":
            event["properties"]["provider"] = provider
            event["properties"]["module"] = module
            event["properties"]["probe"] = probe

        if "args" in cadets_record:
            event["properties"]["args"] = cadets_record["args"]

        event["properties"]["exec"] = cadets_record["exec"]

        for key in cadets_record:
            if not key in cdm_keys: # we already handled the standard CDM keys
                if key in uuid_keys:
                    event["properties"][str(key)] = str(UUID(cadets_record[key]).hex)
                else:
                    event["properties"][str(key)] = str(cadets_record[key])
                # for other keys, (path, fd, address, port, query, request)
                # Store the value in properties

#         if "upath1" in cadets_record:
#             event["properties"]["path"] = cadets_record["upath1"]

        record["datum"] = event

        return record

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
            if call.startswith(key):
                return prefix_dict.get(key)
        return 'EVENT_OS_UNKNOWN'


    def create_subjects(self, event, cadets_record):
        ''' Given a CDM event that we just created, generate Subject instances
            Currently, we create:
              a subject for any files that we discover via the uuids
        '''
        newRecords = []
        if self.createFileObjects and (event["type"] in file_calls or event["properties"]["call"] in file_calls):
            # if this is a file-related event, create events for the uuids on the event.
            # TODO: Make more intelligent, not all or nothing file events
            newRecords = newRecords + self.create_file_subjects(event, cadets_record)

        # NetFlows
        if self.createNetflowObjects and "address" in event["properties"] and "port" in event["properties"]:
            destAddr = event["properties"]["address"]
            destPort = int(event["properties"]["port"])

            self.logger.debug("Creating a NetflowObject from {h}:{p}".format(h=destAddr, p=destPort))
            nf_obj = self.instance_generator.create_netflow_object(destAddr, destPort, self.get_source())
            nf_uuid = nf_obj["datum"]["uuid"]
            newRecords.append(nf_obj)

        return newRecords

    def create_file_subjects(self, event, cadets_record):
        newRecords = []
        for uuid in uuid_keys:
                if uuid in cadets_record:
                    if self.instance_generator.get_file_object_id(cadets_record[uuid]) is None:
                        self.logger.debug("Creating file")
                        fileobj = self.instance_generator.create_file_object(cadets_record.get(uuid), self.get_source())
                        newRecords.append(fileobj)
                else:
                    continue;

        return newRecords
