'''
CADETS JSON record format to TC CDM format translator
'''

import logging
import uuid
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

        proc_uuid = self.instance_generator.get_process_subject_id(cadets_proc_uuid)
        if proc_uuid is None:
            self.logger.debug("Creating new Process Subject for {p}".format(p=pid))
            # We don't know the time when this process was created, so we'll make it 0 for now
            # Could use time as an upper bound, but we'd need to specify

            process_record = self.instance_generator.create_process_subject(pid, cadets_proc_uuid, None, cadets_record["uid"], 0, self.get_source())
            process = process_record["datum"]
            proc_uuid = process["uuid"]

            datums.append(process_record)


        # Create a new Thread subject if necessary
        # TODO:  For now, we'll skip creating the Thread
        tid = cadets_record["tid"]
        if False:
            thread_uuid = self.instance_generator.get_thread_subject_id(tid)
            if thread_uuid is None:
                self.logger.debug("Creating new Thread Subject for {t}".format(t=tid))
                thread = self.instance_generator.create_thread_subject(tid, cadets_record["time"], self.get_source())
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

        # Create related subjects before the event itself
        if "dup" in call:
            # dup2 doesn't provide any new information, since we aren't tracking fds
            return datums

        if "fork" in call: # link forked processes
            new_pid = cadets_record.get("retval")
            new_proc_uuid = cadets_record.get("ret_objuuid1", str(new_pid))

            cproc_uuid = self.instance_generator.get_process_subject_id(new_proc_uuid)
            if cproc_uuid is None:
                proc_record = self.instance_generator.create_process_subject(new_pid, new_proc_uuid, cadets_record["subjprocuuid"], cadets_record["uid"], cadets_record["time"], self.get_source())
                cproc_uuid = proc_record["datum"]["uuid"]
                datums.append(proc_record)

        if "exec" in call: # link exec events to the file executed
            exec_path = cadets_record.get("upath1")
            file_uuid = self.instance_generator.get_file_object_id(cadets_record["arg_objuuid1"])
            if file_uuid is None:
                file_record = self.instance_generator.create_file_object(cadets_record.get("arg_objuuid1"), self.get_source())
                datums.append(file_record)

        # Create the Event
        self.logger.debug("Creating Event from {e} ".format(e=event_type))
        event_record = self.translate_call(provider, module, call, probe, cadets_record)

        event = None
        if event_record != None:
            datums.append(event_record)
            object_records = self.create_subjects(event_record["datum"], cadets_record)
            if object_records != None:
                for objr in object_records:
                    datums.insert(0, objr)


        return datums



    def create_parameters(self, call, cadets_record):
        parameters = []
        if call in ["aue_fchmod", "aue_fchmodat", "aue_lchmod", "aue_chmod"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "mode", cadets_record["mode"]))
            if call in ["aue_fchmodat"]:
                parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "flag", cadets_record["flag"]))
        elif call in ["aue_fchown", "aue_fchownat", "aue_lchown", "aue_chown"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "uid", cadets_record["arg_uid"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "gid", cadets_record["arg_gid"]))
#             if call in ["aue_fchownat"]:
#                 parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "flag", cadets_record["flag"]))
        elif call in ["aue_setresgid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "gid", cadets_record["arg_rgid"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "egid", cadets_record["arg_egid"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "sgid", cadets_record["arg_sgid"]))
        elif call in ["aue_setresuid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "uid", cadets_record["arg_ruid"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "euid", cadets_record["arg_euid"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "suid", cadets_record["arg_suid"]))
        elif call in ["aue_setregid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "gid", cadets_record["arg_rgid"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "egid", cadets_record["arg_egid"]))
        elif call in ["aue_setreuid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "uid", cadets_record["arg_ruid"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "euid", cadets_record["arg_euid"]))
        elif call in ["aue_seteuid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "euid", cadets_record["arg_euid"]))
        elif call in ["aue_setegid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "egid", cadets_record["arg_egid"]))
        elif call in ["aue_setuid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "uid", cadets_record["arg_uid"]))
        elif call in ["aue_setgid"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "gid", cadets_record["arg_gid"]))
        elif call in ["aue_open_rwtc", "aue_openat_rwtc"]:
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "flags", cadets_record["flags"]))
            parameters.append(create_int_parameter("VALUE_TYPE_CONTROL", "mode", cadets_record["mode"]))


#         parameters = {}
#         parameters["size"] = int
#         parameters["type"] = ValueType [VALUE_TYPE_SRC/VALUE_TYPE_SINK/VALUE_TYPE_CONTROL]
#         parameters["valueDataType"] = ValueDataType [VALUE_DATA_TYPE_BYTE/VALUE_DATA_TYPE_CHAR/etc]
#         parameters["isNull"] = bool
#         parameters["name"] = null or string
#         parameters["runtimeDataValue"] = null or string
#         parameters["valueBytes"] = null or bytes
#         parameters["tag"] = None
#         parameters["components"] = noll or [Value]

        return parameters

#     returns (first object acted on, its path, second object acted on, its path, event size)
    def predicates_by_event(self, event, call, cadets_record):
# TODO - combine like events
        if event in ["EVENT_RECVFROM", "EVENT_SENDTO", "EVENT_LSEEK"]:
            return (cadets_record.get("arg_objuuid1"), None, None, None, cadets_record.get("retval"))
        if event in ["EVENT_RENAME"]:
            return (cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), cadets_record.get("arg_objuuid1"), cadets_record.get("upath2"), None)
        if event in ["EVENT_READ", "EVENT_WRITE"]:
            return (cadets_record.get("arg_objuuid1"), cadets_record.get("fdpath"), None, None, cadets_record.get("retval"))
        if event in ["EVENT_MMAP"]:
            return (cadets_record.get("arg_objuuid1"), None, None, None, cadets_record.get("retval"))
        if event in ["EVENT_FORK"]:
            return (cadets_record.get("ret_objuuid1"), None, None, None, None) # fork has a second return uuid. The resulting thread uuid
        if event in ["EVENT_OPEN", "EVENT_CREATE_OBJECT"]:
            return (cadets_record.get("ret_objuuid1"), cadets_record.get("upath1"), None, None, None)
        if event in ["EVENT_LINK"]:
            return (cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), None, cadets_record.get("upath2"), None)
        if event in ["EVENT_EXECUTE"]:
            return (cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), cadets_record.get("arg_objuuid2"), cadets_record.get("upath2"), None)
        if event in ["EVENT_CLOSE", "EVENT_MODIFY_FILE_ATTRIBUTES", "EVENT_UNLINK", "EVENT_UPDATE_OBJECT", "EVENT_TRUNCATE"]:
            return (cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), None, None, None)
        if event in ["EVENT_CHANGE_PRINCIPAL", "EVENT_EXIT"]:
            return (cadets_record.get("subjprocuuid"), None, None, None, None) # is acting on itself
        if event in ["EVENT_OTHER"] and call == "aue_pipe":
            return (cadets_record.get("ret_objuuid1"), None, cadets_record.get("ret_objuuid2"), None, None)
        if event in ["EVENT_OTHER"] and call in ["aue_fchdir", "aue_chdir"]:
            return (cadets_record.get("subjprocuuid"), None, cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), None)
        if event in ["EVENT_OTHER"] and call in ["aue_symlink", "aue_symlinkat"]:
            return (cadets_record.get("ret_objuuid1"), cadets_record.get("upath1"), None, None, None)
        if event in ["EVENT_OTHER"] and call in ["aue_umask"]:
            return (cadets_record.get("subjprocuuid"), None, None, None, None) # is acting on itself
        print("Unhandled event/call: {}/{}\n".format(event, call))
        return (cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), cadets_record.get("arg_objuuid2"), cadets_record.get("upath2"), None)

    def translate_call(self, provider, module, call, probe, cadets_record):
        ''' Translate a system or function call event '''

        record = {}
        event = {}


        event["subject"] = self.instance_generator.create_uuid("uuid", uuid.UUID(cadets_record["subjprocuuid"]).int)
        event_uuid = self.instance_generator.create_uuid("event", self.eventCounter)
        (pred_obj, pred_obj_path, pred_obj2, pred_obj2_path, size) = self.predicates_by_event(self.convert_audit_event_type(call), call, cadets_record);
        if pred_obj:
            event["predicateObject"] = self.instance_generator.create_uuid("uuid", uuid.UUID(pred_obj).int)
        else:
            # TODO - Once we know why this is missing so much, drop the warning
            self.logger.warn("No predicate object for record: %s", cadets_record);
        if pred_obj_path:
            event["predicateObjectPath"] = pred_obj_path
        if pred_obj2:
            event["predicateObject2"] = self.instance_generator.create_uuid("uuid", uuid.UUID(pred_obj2).int)
        if pred_obj2_path:
            event["predicateObject2Path"] = pred_obj2_path
        event["name"] = call
        event["parameters"] = self.create_parameters(call, cadets_record) # [Values] #TODO
#         event["location"] = long
        if size:
            event["size"] = size
#         event["programPoint"] = string
        event["properties"] = {}
        event["uuid"] = event_uuid
        if provider == "audit":
            event["type"] = self.convert_audit_event_type(call)
        else:
            self.logger.warn("Unexpected provider %s", provider)
            return None

        event["timestampNanos"] = cadets_record["time"]

        # Use the event counter as the seq number
        # This assumes we're processing events in order
        event["sequence"] = self.eventCounter
        self.eventCounter += 1

        if "args" in cadets_record:
            event["properties"]["args"] = cadets_record["args"]

        event["properties"]["exec"] = cadets_record["exec"]

        event["threadId"] = cadets_record["tid"]

        record["CDMVersion"] = self.CDMVersion
        record["source"] = self.get_source()
        record["datum"] = event

        return record

    def convert_audit_event_type(self, call):
        ''' Convert the call to one of the CDM EVENT types, since there are specific types defined for common syscalls
            Fallthrough default is EVENT_OTHER
        '''
        prefix_dict = {'aue_execve' : 'EVENT_EXECUTE',
                       'aue_accept' : 'EVENT_ACCEPT',
                       'aue_bind' : 'EVENT_BIND',
                       'aue_close' : 'EVENT_CLOSE',
                       'aue_lseek' : 'EVENT_LSEEK',
                       'aue_connect' : 'EVENT_CONNECT',
                       'aue_fchdir' : 'EVENT_OTHER',
                       'aue_exit' : 'EVENT_EXIT',
                       'aue_fork' : 'EVENT_FORK',
                       'aue_vfork' : 'EVENT_FORK',
                       'aue_rfork' : 'EVENT_FORK',
                       'aue_setuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setgid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_seteuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setegid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setreuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setreuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setresgid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setresuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_chmod' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_fchmod' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_lchmod' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_chown' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_fchown' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_lchown' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_futimes' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_lutimes' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_utimes' : 'EVENT_MODIFY_FILE_ATTRIBUTES',
                       'aue_link' : 'EVENT_LINK',
                       'aue_unlink' : 'EVENT_UNLINK',
                       'aue_mmap' : 'EVENT_MMAP',
                       'aue_mkdir' : 'EVENT_CREATE_OBJECT',
                       'aue_rmdir' : 'EVENT_UNLINK',
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
        return 'EVENT_OTHER'


    def create_subjects(self, event, cadets_record):
        ''' Given a CDM event that we just created, generate Subject instances
            Currently, we create:
              a subject for any files that we discover via the uuids
        '''
        newRecords = []
        if self.createFileObjects and (event["type"] in file_calls or event["name"] in file_calls):
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

def create_int_parameter(value_type, name, value):
        parameter = {}
        parameter["size"] = -1 # -1 = primitive
        parameter["type"] = value_type
        parameter["valueDataType"]="VALUE_DATA_TYPE_INT"
        parameter["isNull"] = False
        parameter["name"] = name
        parameter["valueBytes"] = value
        return parameter
