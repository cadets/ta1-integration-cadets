'''
CADETS JSON record format to TC CDM format translator
'''

import logging
import uuid
from instance_generator import InstanceGenerator

# These calls will have files as their parameters
file_calls = ["EVENT_UNLINKAT", "EVENT_UNLINK", "EVENT_RENAME", "EVENT_MMAP",
  "EVENT_TRUNCATE", "EVENT_EXECUTE", "EVENT_OPEN", "EVENT_CLOSE", "EVENT_READ",
  "EVENT_WRITE", "EVENT_MODIFY_FILE_ATTRIBUTES", "EVENT_LSEEK",
  "aue_symlink", "aue_symlinkat"] # TODO not complete list
# these are the keys that may contain interesting UUIDs
uuid_keys = ["arg_objuuid1", "arg_objuuid2", "ret_objuuid1", "ret_objuuid2"]

class CDMTranslator(object):

    # True: Raise an exception if we can't translate a record
    # False: just log it
    exceptionOnError = True

    # Event counter, used for unique ids
    eventCounter = 0

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

        # dispatch based on type
        event_type = cadets_record["event"]
        event_components = event_type.split(":")
        if len(event_components) < 4:
            self.handle_error("Expecting 4 elements in the event type: provider:module:function:probe. Got: "+event_type)

        provider = event_components[0]
        module = event_components[1]
        call = event_components[2]
        probe = event_components[3]

        # Handle socket info - the CADETS record is missing most normal record info
        if provider == "fbt" and call == "cc_conn_init":
            nf_obj = self.instance_generator.create_netflow_object(cadets_record["faddr"], cadets_record["fport"], cadets_record["so_uuid"], self.get_source(), cadets_record["laddr"], cadets_record["lport"])
            datums.append(nf_obj)
            return datums
        # Create a new user if necessary
        uid = cadets_record["uid"]
        if not self.instance_generator.get_user_id(uid):
            self.logger.debug("Creating new User Principal for {u}".format(u=uid))
            principal = self.instance_generator.create_user_principal(uid, self.get_source())
            datums.append(principal)

        # Create a new Process subject if necessary
        pid = cadets_record["pid"]
        ppid = cadets_record.get("ppid", -1)
        cadets_proc_uuid = cadets_record.get("subjprocuuid", str(cadets_record["pid"]))

        if not self.instance_generator.is_known_object(cadets_proc_uuid):
            self.logger.debug("Creating new Process Subject for {p}".format(p=pid))
            # We don't know the time when this process was created, so we'll make it 0 for now
            # Could use time as an upper bound, but we'd need to specify

            process_record = self.instance_generator.create_process_subject(pid, cadets_proc_uuid, None, cadets_record["uid"], 0, self.get_source())
            process = process_record["datum"]

            datums.append(process_record)


        # Create a new Thread subject if necessary
        # TODO:  For now, we'll skip creating the Thread
        tid = cadets_record["tid"]
        if False:
            if not self.instance_generator.get_thread_subject_id(tid):
                self.logger.debug("Creating new Thread Subject for {t}".format(t=tid))
                thread = self.instance_generator.create_thread_subject(tid, cadets_record["time"], self.get_source())
                datums.append(thread)


        # Create related subjects before the event itself
        if "fork" in call: # link forked processes
            new_pid = cadets_record.get("retval")
            new_proc_uuid = cadets_record.get("ret_objuuid1", str(new_pid))

            if not self.instance_generator.is_known_object(new_proc_uuid):
                proc_record = self.instance_generator.create_process_subject(new_pid, new_proc_uuid, cadets_record["subjprocuuid"], cadets_record["uid"], cadets_record["time"], self.get_source())
                datums.append(proc_record)
        elif "kill" in call:
            killed_pid = cadets_record.get("arg_pid")
            killed_uuid = cadets_record.get("arg_objuuid1")

            if killed_uuid and not self.instance_generator.is_known_object(killed_uuid):
                # We only discovered the process when it was killed, so our
                # info is limited.
                proc_record = self.instance_generator.create_process_subject(killed_pid, killed_uuid, None, -1, 0, self.get_source())
                datums.append(proc_record)
        elif "exec" in call: # link exec events to the file executed
            exec_path = cadets_record.get("upath1")
            if not self.instance_generator.is_known_object(cadets_record["arg_objuuid1"]):
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
            parameters.append(create_int_parameter("CONTROL", "mode", cadets_record.get("mode")))
            if call in ["aue_fchmodat"]:
                parameters.append(create_int_parameter("CONTROL", "flag", cadets_record.get("flag")))
        elif call in ["aue_fchown", "aue_fchownat", "aue_lchown", "aue_chown"]:
            parameters.append(create_int_parameter("CONTROL", "uid", cadets_record.get("arg_uid")))
            parameters.append(create_int_parameter("CONTROL", "gid", cadets_record.get("arg_gid")))
#             if call in ["aue_fchownat"]:
#                 parameters.append(create_int_parameter("CONTROL", "flag", cadets_record.get("flag")))
        elif call in ["aue_setresgid"]:
            parameters.append(create_int_parameter("CONTROL", "gid", cadets_record.get("arg_rgid")))
            parameters.append(create_int_parameter("CONTROL", "egid", cadets_record.get("arg_egid")))
            parameters.append(create_int_parameter("CONTROL", "sgid", cadets_record.get("arg_sgid")))
        elif call in ["aue_setresuid"]:
            parameters.append(create_int_parameter("CONTROL", "uid", cadets_record.get("arg_ruid")))
            parameters.append(create_int_parameter("CONTROL", "euid", cadets_record.get("arg_euid")))
            parameters.append(create_int_parameter("CONTROL", "suid", cadets_record.get("arg_suid")))
        elif call in ["aue_setregid"]:
            parameters.append(create_int_parameter("CONTROL", "gid", cadets_record.get("arg_rgid")))
            parameters.append(create_int_parameter("CONTROL", "egid", cadets_record.get("arg_egid")))
        elif call in ["aue_setreuid"]:
            parameters.append(create_int_parameter("CONTROL", "uid", cadets_record.get("arg_ruid")))
            parameters.append(create_int_parameter("CONTROL", "euid", cadets_record.get("arg_euid")))
        elif call in ["aue_seteuid"]:
            parameters.append(create_int_parameter("CONTROL", "euid", cadets_record.get("arg_euid")))
        elif call in ["aue_setegid"]:
            parameters.append(create_int_parameter("CONTROL", "egid", cadets_record.get("arg_egid")))
        elif call in ["aue_setuid"]:
            parameters.append(create_int_parameter("CONTROL", "uid", cadets_record.get("arg_uid")))
        elif call in ["aue_setgid"]:
            parameters.append(create_int_parameter("CONTROL", "gid", cadets_record.get("arg_gid")))
        elif call in ["aue_kill"]:
            parameters.append(create_int_parameter("CONTROL", "pid", cadets_record.get("arg_pid")))
            parameters.append(create_int_parameter("CONTROL", "signum", cadets_record.get("signum")))
        elif call in ["aue_open_rwtc", "aue_openat_rwtc"]:
            parameters.append(create_int_parameter("CONTROL", "flags", cadets_record.get("flags")))
            parameters.append(create_int_parameter("CONTROL", "mode", cadets_record.get("mode")))
        elif call in ["aue_fcntl"]:
            parameters.append(create_int_parameter("CONTROL", "cmd", cadets_record.get("fcntl_cmd")))


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
        if event in ["EVENT_RECVMSG", "EVENT_RECVFROM", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_LSEEK", "EVENT_MMAP"]:
            return (cadets_record.get("arg_objuuid1"), None, None, None, cadets_record.get("retval"))
        if event in ["EVENT_ACCEPT"]:
            return (cadets_record.get("arg_objuuid1"), None, cadets_record.get("ret_objuuid1"), None, None)
        if event in ["EVENT_RENAME"]:
            return (cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), cadets_record.get("arg_objuuid1"), cadets_record.get("upath2"), None)
        if event in ["EVENT_READ", "EVENT_WRITE"]:
            return (cadets_record.get("arg_objuuid1"), cadets_record.get("fdpath"), None, None, cadets_record.get("retval"))
        if event in ["EVENT_FORK"]:
            return (cadets_record.get("ret_objuuid1"), None, None, None, None) # fork has a second return uuid. The resulting thread uuid
        if event in ["EVENT_CREATE_OBJECT"] and call in ["aue_pipe", "aue_socketpair"]:
            return (cadets_record.get("ret_objuuid1"), None, cadets_record.get("ret_objuuid2"), None, None)
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
        if event in ["EVENT_SIGNAL"] and call == "aue_kill":
            return (cadets_record.get("arg_objuuid1"), None, None, None, None)
        if event in ["EVENT_MODIFY_PROCESS"] and call in ["aue_fchdir", "aue_chdir"]:
            return (cadets_record.get("subjprocuuid"), None, cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), None)
        if event in ["EVENT_CREATE_OBJECT"] and call in ["aue_symlink", "aue_symlinkat"]:
            return (cadets_record.get("ret_objuuid1"), cadets_record.get("upath1"), None, None, None)
        if event in ["EVENT_MODIFY_PROCESS"] and call in ["aue_umask"]:
            return (cadets_record.get("subjprocuuid"), None, None, None, None) # is acting on itself
        if event in ["EVENT_CONNECT", "EVENT_FNCTL", "EVENT_BIND"]:
            return (cadets_record.get("arg_objuuid1"), None, None, None, None)
        if event in ["EVENT_LOGIN"]:
            return (None, None, None, None, None)
        if event in ["EVENT_OTHER"] and call in ["aue_listen"]:
            return (cadets_record.get("arg_objuuid1"), None, None, None, None)
        self.logger.warn("Unhandled event/call: %s/%s\n", event, call)
        return (cadets_record.get("arg_objuuid1"), cadets_record.get("upath1"), cadets_record.get("arg_objuuid2"), cadets_record.get("upath2"), None)

    def translate_call(self, provider, module, call, probe, cadets_record):
        ''' Translate a system or function call event '''

        record = {}
        event = {}

        if provider == "audit":
            event["type"] = self.convert_audit_event_type(call)
        else:
            self.logger.warn("Unexpected provider %s", provider)
            return None
        if call in ["aue_socket"]:
            self.logger.debug("Skipping socket call")
            return None
        if event["type"] is None:
            self.logger.debug("Skipping event %s", call)
            return None

        event["subject"] = self.instance_generator.create_uuid("uuid", uuid.UUID(cadets_record["subjprocuuid"]).int)
        event_uuid = self.instance_generator.create_uuid("event", self.eventCounter)
        (pred_obj, pred_obj_path, pred_obj2, pred_obj2_path, size) = self.predicates_by_event(event["type"], call, cadets_record);
        if pred_obj:
            event["predicateObject"] = self.instance_generator.create_uuid("uuid", uuid.UUID(pred_obj).int)
        elif call in ["aue_close", "aue_closefrom"]:
            # Close is often missing a predicate, and is thus useless
            # Closefrom doesn't specify everything it closes
            return None

        if pred_obj_path:
            event["predicateObjectPath"] = pred_obj_path
        if pred_obj2:
            event["predicateObject2"] = self.instance_generator.create_uuid("uuid", uuid.UUID(pred_obj2).int)
        if pred_obj2_path:
            event["predicateObject2Path"] = pred_obj2_path
        event["name"] = call
        event["parameters"] = self.create_parameters(call, cadets_record) # [Values]
#         event["location"] = long
        if size is not None:
            event["size"] = size
        elif "len" in cadets_record:
            event["size"] = cadets_record["len"]
#         event["programPoint"] = string
        event["properties"] = {}
        event["uuid"] = event_uuid

        event["timestampNanos"] = cadets_record["time"]

        # Use the event counter as the seq number
        # This assumes we're processing events in order
        event["sequence"] = self.eventCounter
        self.eventCounter += 1

        # Put these possibly interesting thing in properties
        for key, val in cadets_record.items():
            if (key not in uuid_keys
                and (key.startswith("ret_")
                    or key.startswith("arg_"))):
                event["properties"][key] = str(val)
        if "args" in cadets_record:
            event["properties"]["args"] = cadets_record["args"]
        if "login" in cadets_record:
            event["properties"]["login"] = str(cadets_record["login"])
        if "fdpath" in cadets_record:
            event["properties"]["partial_path"] = str(cadets_record["fdpath"])
        if "fd" in cadets_record:
            event["properties"]["fd"] = str(cadets_record["fd"])
        if "retval" in cadets_record and "size" not in event:
            event["properties"]["return_value"] = str(cadets_record["retval"])
        if "cmdline" in cadets_record:
            event["properties"]["cmdLine"] = str(cadets_record["cmdline"])
        if "ppid" in cadets_record:
            event["properties"]["ppid"] = str(cadets_record["ppid"])
        if "address" in cadets_record:
            event["properties"]["address"] = str(cadets_record["address"])
        if "port" in cadets_record:
            event["properties"]["port"] = str(cadets_record["port"])

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
                       'aue_fchdir' : 'EVENT_MODIFY_PROCESS',
                       'aue_chdir' : 'EVENT_MODIFY_PROCESS',
                       'aue_umask' : 'EVENT_MODIFY_PROCESS',
                       'aue_exit' : 'EVENT_EXIT',
                       'aue_pdfork' : 'EVENT_FORK',
                       'aue_fork' : 'EVENT_FORK',
                       'aue_vfork' : 'EVENT_FORK',
                       'aue_rfork' : 'EVENT_FORK',
                       'aue_setuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setgid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_seteuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setegid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setreuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setregid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setresgid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_setresuid' : 'EVENT_CHANGE_PRINCIPAL',
                       'aue_fcntl' : 'EVENT_FNCTL',
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
                       'aue_pipe' : 'EVENT_CREATE_OBJECT',
                       'aue_read' : 'EVENT_READ',
                       'aue_pread' : 'EVENT_READ',
                       'aue_write' : 'EVENT_WRITE',
                       'aue_pwrite' : 'EVENT_WRITE',
                       'aue_rename' : 'EVENT_RENAME',
                       'aue_sendto' : 'EVENT_SENDTO',
                       'aue_sendmsg' : 'EVENT_SENDMSG',
                       'aue_symlink' : 'EVENT_CREATE_OBJECT',
                       'aue_recvfrom' : 'EVENT_RECVFROM',
                       'aue_recvmsg' : 'EVENT_RECVMSG',
                       'aue_pdkill' : 'EVENT_SIGNAL',
                       'aue_kill' : 'EVENT_SIGNAL',
                       'aue_truncate' : 'EVENT_TRUNCATE',
                       'aue_ftruncate' : 'EVENT_TRUNCATE',
                       'aue_wait' : 'EVENT_WAIT',
                       'aue_setlogin' : 'EVENT_LOGIN',
                       'aue_shm' : 'EVENT_SHM',
                       'aue_socket' : 'EVENT_CREATE_OBJECT',
                       'aue_dup' : None
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
        if event["type"] in file_calls or event["name"] in file_calls:
            # if this is a file-related event, create events for the uuids on the event.
            # TODO: Make more intelligent, not all or nothing file events
            newRecords = newRecords + self.create_file_subjects(event, cadets_record)
        if event["name"] in ["aue_chdir", "aue_fchdir"]:
            if not self.instance_generator.is_known_object(cadets_record["arg_objuuid1"]):
                newRecords.append(self.instance_generator.create_file_object(cadets_record["arg_objuuid1"], self.get_source(), is_dir=True))
        if event["name"] in ["aue_mkdir"]:
            if not self.instance_generator.is_known_object(cadets_record["ret_objuuid1"]):
                newRecords.append(self.instance_generator.create_file_object(cadets_record["ret_objuuid1"], self.get_source(), is_dir=True))

        # NetFlows and sockets
        if event["name"] in ["aue_pipe", "aue_pipe2"]:
            # Create something to link the two endpoints of the pipe
            pipe_uuid1 = cadets_record.get("ret_objuuid1")
            pipe_uuid2 = cadets_record.get("ret_objuuid2")
            pipe_obj = self.instance_generator.create_pipe_object(pipe_uuid1, self.get_source())
            pipe_obj2 = self.instance_generator.create_pipe_object(pipe_uuid2, self.get_source())
            newRecords.append(pipe_obj)
            newRecords.append(pipe_obj2)
        elif event["name"] in ["aue_socket", "aue_socketpair"]:
            socket = cadets_record.get("ret_objuuid1")
            if not self.instance_generator.is_known_object(socket):
                self.logger.debug("Creating a UnixSocket from socket call")
                nf_obj = self.instance_generator.create_unix_socket_object(socket, self.get_source())
                newRecords.append(nf_obj)
            socket2 = cadets_record.get("ret_objuuid2")
            if socket2 and not self.instance_generator.is_known_object(socket2):
                self.logger.debug("Creating a UnixSocket from socket call")
                nf_obj = self.instance_generator.create_unix_socket_object(socket2, self.get_source())
                newRecords.append(nf_obj)
        elif event["type"] in ["EVENT_BIND"]:
            localAddr = cadets_record.get("address")
            localPort = cadets_record.get("port")
            listening_socket = cadets_record.get("arg_objuuid1")
            if not self.instance_generator.is_known_object(listening_socket):
                self.logger.debug("Creating a UnixSocket from {h}".format(h=localAddr))
                nf_obj = self.instance_generator.create_unix_socket_object(listening_socket, self.get_source())
                newRecords.append(nf_obj)
        elif event["type"] in ["EVENT_ACCEPT"]:
            remoteAddr = cadets_record.get("address")
            remotePort = cadets_record.get("port")
            listening_socket = cadets_record.get("arg_objuuid1")
            if not self.instance_generator.is_known_object(listening_socket):
                self.logger.debug("Creating a UnixSocket from {h}".format(h=remoteAddr))
                nf_obj = self.instance_generator.create_unix_socket_object(listening_socket, self.get_source())
                newRecords.append(nf_obj)
            accepted_socket = cadets_record.get("ret_objuuid1") # accepted socket
            if not self.instance_generator.is_known_object(accepted_socket):
                if remotePort:
                    self.logger.debug("Creating a NetflowObject from {h}:{p}".format(h=remoteAddr, p=remotePort))
                    nf_obj = self.instance_generator.create_netflow_object(remoteAddr, remotePort, accepted_socket, self.get_source())
                    newRecords.append(nf_obj)
                else:
                    self.logger.debug("Creating a UnixSocket from {h}".format(h=remoteAddr))
                    nf_obj = self.instance_generator.create_unix_socket_object(accepted_socket, self.get_source())
                    newRecords.append(nf_obj)
        elif event["type"] in ["EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVMSG", "EVENT_SENDMSG", "EVENT_RECVFROM"]:
            socket_uuid = cadets_record.get("arg_objuuid1")
            if not self.instance_generator.is_known_object(socket_uuid):
                remoteAddr = cadets_record.get("address")
                remotePort = cadets_record.get("port")

                if remotePort:
                    self.logger.debug("Creating a NetflowObject from {h}:{p}".format(h=remoteAddr, p=remotePort))
                    nf_obj = self.instance_generator.create_netflow_object(remoteAddr, remotePort, socket_uuid, self.get_source())
                    newRecords.append(nf_obj)
                else:
                    self.logger.debug("Creating a UnixSocket from {h}".format(h=remoteAddr))
                    nf_obj = self.instance_generator.create_unix_socket_object(socket_uuid, self.get_source())
                    newRecords.append(nf_obj)

        return newRecords

    def create_file_subjects(self, event, cadets_record):
        newRecords = []
        for uuid in uuid_keys:
                if uuid in cadets_record:
                    if not self.instance_generator.is_known_object(cadets_record[uuid]):
                        self.logger.debug("Creating file")
                        # TODO determine if it's a directory first
                        fileobj = self.instance_generator.create_file_object(cadets_record.get(uuid), self.get_source())
                        newRecords.append(fileobj)
                else:
                    continue;

        return newRecords

def create_int_parameter(value_type, name, value):
        parameter = {}
        parameter["size"] = -1 # -1 = primitive
        parameter["type"] = "VALUE_TYPE_" + value_type
        parameter["valueDataType"]="VALUE_DATA_TYPE_INT"
        parameter["isNull"] = value is None
        parameter["name"] = name
        if not value is None:
            # encodes, and uses 2s complement if needed.
            parameter["valueBytes"] = value.to_bytes((value.bit_length()+8) // 8, "big", signed=True)
        return parameter
