// generated file; DO NOT EDIT - use go generate in directory with source

package capability

import "strings"

func (c Cap) String() string {
	switch c {
	case CAP_CHOWN:
		return "chown"
	case CAP_DAC_OVERRIDE:
		return "dac_override"
	case CAP_DAC_READ_SEARCH:
		return "dac_read_search"
	case CAP_FOWNER:
		return "fowner"
	case CAP_FSETID:
		return "fsetid"
	case CAP_KILL:
		return "kill"
	case CAP_SETGID:
		return "setgid"
	case CAP_SETUID:
		return "setuid"
	case CAP_SETPCAP:
		return "setpcap"
	case CAP_LINUX_IMMUTABLE:
		return "linux_immutable"
	case CAP_NET_BIND_SERVICE:
		return "net_bind_service"
	case CAP_NET_BROADCAST:
		return "net_broadcast"
	case CAP_NET_ADMIN:
		return "net_admin"
	case CAP_NET_RAW:
		return "net_raw"
	case CAP_IPC_LOCK:
		return "ipc_lock"
	case CAP_IPC_OWNER:
		return "ipc_owner"
	case CAP_SYS_MODULE:
		return "sys_module"
	case CAP_SYS_RAWIO:
		return "sys_rawio"
	case CAP_SYS_CHROOT:
		return "sys_chroot"
	case CAP_SYS_PTRACE:
		return "sys_ptrace"
	case CAP_SYS_PACCT:
		return "sys_pacct"
	case CAP_SYS_ADMIN:
		return "sys_admin"
	case CAP_SYS_BOOT:
		return "sys_boot"
	case CAP_SYS_NICE:
		return "sys_nice"
	case CAP_SYS_RESOURCE:
		return "sys_resource"
	case CAP_SYS_TIME:
		return "sys_time"
	case CAP_SYS_TTY_CONFIG:
		return "sys_tty_config"
	case CAP_MKNOD:
		return "mknod"
	case CAP_LEASE:
		return "lease"
	case CAP_AUDIT_WRITE:
		return "audit_write"
	case CAP_AUDIT_CONTROL:
		return "audit_control"
	case CAP_SETFCAP:
		return "setfcap"
	case CAP_MAC_OVERRIDE:
		return "mac_override"
	case CAP_MAC_ADMIN:
		return "mac_admin"
	case CAP_SYSLOG:
		return "syslog"
	case CAP_WAKE_ALARM:
		return "wake_alarm"
	case CAP_BLOCK_SUSPEND:
		return "block_suspend"
	case CAP_AUDIT_READ:
		return "audit_read"
	case CAP_PERFMON:
		return "perfmon"
	case CAP_BPF:
		return "bpf"
	case CAP_CHECKPOINT_RESTORE:
		return "checkpoint_restore"
	}
	return "unknown"
}

// List returns list of all supported capabilities
func List() []Cap {
	return []Cap{
		CAP_CHOWN,
		CAP_DAC_OVERRIDE,
		CAP_DAC_READ_SEARCH,
		CAP_FOWNER,
		CAP_FSETID,
		CAP_KILL,
		CAP_SETGID,
		CAP_SETUID,
		CAP_SETPCAP,
		CAP_LINUX_IMMUTABLE,
		CAP_NET_BIND_SERVICE,
		CAP_NET_BROADCAST,
		CAP_NET_ADMIN,
		CAP_NET_RAW,
		CAP_IPC_LOCK,
		CAP_IPC_OWNER,
		CAP_SYS_MODULE,
		CAP_SYS_RAWIO,
		CAP_SYS_CHROOT,
		CAP_SYS_PTRACE,
		CAP_SYS_PACCT,
		CAP_SYS_ADMIN,
		CAP_SYS_BOOT,
		CAP_SYS_NICE,
		CAP_SYS_RESOURCE,
		CAP_SYS_TIME,
		CAP_SYS_TTY_CONFIG,
		CAP_MKNOD,
		CAP_LEASE,
		CAP_AUDIT_WRITE,
		CAP_AUDIT_CONTROL,
		CAP_SETFCAP,
		CAP_MAC_OVERRIDE,
		CAP_MAC_ADMIN,
		CAP_SYSLOG,
		CAP_WAKE_ALARM,
		CAP_BLOCK_SUSPEND,
		CAP_AUDIT_READ,
		CAP_PERFMON,
		CAP_BPF,
		CAP_CHECKPOINT_RESTORE,
	}
}

func Parse(s string) (Cap, bool) {
	s = strings.TrimPrefix(strings.ToLower(s), "cap_")
	switch s {
	case "chown":
		return CAP_CHOWN, true
	case "dac_override":
		return CAP_DAC_OVERRIDE, true
	case "dac_read_search":
		return CAP_DAC_READ_SEARCH, true
	case "fowner":
		return CAP_FOWNER, true
	case "fsetid":
		return CAP_FSETID, true
	case "kill":
		return CAP_KILL, true
	case "setgid":
		return CAP_SETGID, true
	case "setuid":
		return CAP_SETUID, true
	case "setpcap":
		return CAP_SETPCAP, true
	case "linux_immutable":
		return CAP_LINUX_IMMUTABLE, true
	case "net_bind_service":
		return CAP_NET_BIND_SERVICE, true
	case "net_broadcast":
		return CAP_NET_BROADCAST, true
	case "net_admin":
		return CAP_NET_ADMIN, true
	case "net_raw":
		return CAP_NET_RAW, true
	case "ipc_lock":
		return CAP_IPC_LOCK, true
	case "ipc_owner":
		return CAP_IPC_OWNER, true
	case "sys_module":
		return CAP_SYS_MODULE, true
	case "sys_rawio":
		return CAP_SYS_RAWIO, true
	case "sys_chroot":
		return CAP_SYS_CHROOT, true
	case "sys_ptrace":
		return CAP_SYS_PTRACE, true
	case "sys_pacct":
		return CAP_SYS_PACCT, true
	case "sys_admin":
		return CAP_SYS_ADMIN, true
	case "sys_boot":
		return CAP_SYS_BOOT, true
	case "sys_nice":
		return CAP_SYS_NICE, true
	case "sys_resource":
		return CAP_SYS_RESOURCE, true
	case "sys_time":
		return CAP_SYS_TIME, true
	case "sys_tty_config":
		return CAP_SYS_TTY_CONFIG, true
	case "mknod":
		return CAP_MKNOD, true
	case "lease":
		return CAP_LEASE, true
	case "audit_write":
		return CAP_AUDIT_WRITE, true
	case "audit_control":
		return CAP_AUDIT_CONTROL, true
	case "setfcap":
		return CAP_SETFCAP, true
	case "mac_override":
		return CAP_MAC_OVERRIDE, true
	case "mac_admin":
		return CAP_MAC_ADMIN, true
	case "syslog":
		return CAP_SYSLOG, true
	case "wake_alarm":
		return CAP_WAKE_ALARM, true
	case "block_suspend":
		return CAP_BLOCK_SUSPEND, true
	case "audit_read":
		return CAP_AUDIT_READ, true
	case "perfmon":
		return CAP_PERFMON, true
	case "bpf":
		return CAP_BPF, true
	case "checkpoint_restore":
		return CAP_CHECKPOINT_RESTORE, true
	}
	return -1, false
}
