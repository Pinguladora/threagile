/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Protocol int

const (
	UnknownProtocol Protocol = iota
	HTTP
	HTTPS
	WS
	WSS
	ReverseProxyWebProtocol
	ReverseProxyWebProtocolEncrypted
	MQTT
	JDBC
	JdbcEncrypted
	ODBC
	OdbcEncrypted
	SqlAccessProtocol
	SqlAccessProtocolEncrypted
	NosqlAccessProtocol
	NosqlAccessProtocolEncrypted
	BINARY
	BinaryEncrypted
	TEXT
	TextEncrypted
	SSH
	SshTunnel
	SMTP
	SmtpEncrypted
	POP3
	Pop3Encrypted
	IMAP
	ImapEncrypted
	FTP
	FTPS
	SFTP
	SCP
	LDAP
	LDAPS
	JMS
	NFS
	SMB
	SmbEncrypted
	LocalFileAccess
	NRPE
	XMPP
	IIOP
	IiopEncrypted
	JRMP
	JrmpEncrypted
	InProcessLibraryCall
	InterProcessCommunication
	ContainerSpawning
)

func ProtocolValues() []TypeEnum {
	return []TypeEnum{
		UnknownProtocol,
		HTTP,
		HTTPS,
		WS,
		WSS,
		ReverseProxyWebProtocol,
		ReverseProxyWebProtocolEncrypted,
		MQTT,
		JDBC,
		JdbcEncrypted,
		ODBC,
		OdbcEncrypted,
		SqlAccessProtocol,
		SqlAccessProtocolEncrypted,
		NosqlAccessProtocol,
		NosqlAccessProtocolEncrypted,
		BINARY,
		BinaryEncrypted,
		TEXT,
		TextEncrypted,
		SSH,
		SshTunnel,
		SMTP,
		SmtpEncrypted,
		POP3,
		Pop3Encrypted,
		IMAP,
		ImapEncrypted,
		FTP,
		FTPS,
		SFTP,
		SCP,
		LDAP,
		LDAPS,
		JMS,
		NFS,
		SMB,
		SmbEncrypted,
		LocalFileAccess,
		NRPE,
		XMPP,
		IIOP,
		IiopEncrypted,
		JRMP,
		JrmpEncrypted,
		InProcessLibraryCall,
		InterProcessCommunication,
		ContainerSpawning,
	}
}

var ProtocolTypeDescription = [...]TypeDescription{
	{"unknown-protocol", "Unknown protocol"},
	{"http", "HTTP protocol"},
	{"https", "HTTPS protocol (encrypted)"},
	{"ws", "WebSocket"},
	{"wss", "WebSocket but encrypted"},
	{"reverse-proxy-web-protocol", "Protocols used by reverse proxies"},
	{"reverse-proxy-web-protocol-encrypted", "Protocols used by reverse proxies but encrypted"},
	{"mqtt", "MQTT Message protocol. Encryption via TLS is optional"},
	{"jdbc", "Java Database Connectivity"},
	{"jdbc-encrypted", "Java Database Connectivity but encrypted"},
	{"odbc", "Open Database Connectivity"},
	{"odbc-encrypted", "Open Database Connectivity but encrypted"},
	{"sql-access-protocol", "SQL access protocol"},
	{"sql-access-protocol-encrypted", "SQL access protocol but encrypted"},
	{"nosql-access-protocol", "NOSQL access protocol"},
	{"nosql-access-protocol-encrypted", "NOSQL access protocol but encrypted"},
	{"binary", "Some other binary protocol"},
	{"binary-encrypted", "Some other binary protocol, encrypted"},
	{"text", "Some other text protocol"},
	{"text-encrypted", "Some other text protocol, encrypted"},
	{"ssh", "Secure Shell to execute commands"},
	{"ssh-tunnel", "Secure Shell as a tunnel"},
	{"smtp", "Mail transfer protocol (sending)"},
	{"smtp-encrypted", "Mail transfer protocol (sending), encrypted"},
	{"pop3", "POP 3 mail fetching"},
	{"pop3-encrypted", "POP 3 mail fetching, encrypted"},
	{"imap", "IMAP mail sync protocol"},
	{"imap-encrypted", "IMAP mail sync protocol, encrypted"},
	{"ftp", "File Transfer Protocol"},
	{"ftps", "FTP with TLS"},
	{"sftp", "FTP on SSH"},
	{"scp", "Secure Shell to copy files"},
	{"ldap", "Lightweight Directory Access Protocol - User directories"},
	{"ldaps", "Lightweight Directory Access Protocol - User directories on TLS"},
	{"jms", "Jakarta Messaging"},
	{"nfs", "Network File System"},
	{"smb", "Server Message Block"},
	{"smb-encrypted", "Server Message Block, but encrypted"},
	{"local-file-access", "Data files are on the local system"},
	{"nrpe", "Nagios Remote Plugin Executor"},
	{"xmpp", "Extensible Messaging and Presence Protocol"},
	{"iiop", "Internet Inter-ORB Protocol "},
	{"iiop-encrypted", "Internet Inter-ORB Protocol , encrypted"},
	{"jrmp", "Java Remote Method Protocol"},
	{"jrmp-encrypted", "Java Remote Method Protocol, encrypted"},
	{"in-process-library-call", "Call to local library"},
	{"inter-process-communication", "Communication between processes via system sockets or systems like dbus"},
	{"container-spawning", "Spawn a container"},
}

func ParseProtocol(value string) (protocol Protocol, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range ProtocolValues() {
		if parsed, ok := candidate.(Protocol); ok && parsed.String() == value {
			return parsed, err
		}
	}
	return protocol, fmt.Errorf("unable to parse into type: %v", value)
}

func (what Protocol) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return ProtocolTypeDescription[what].Name
}

func (what Protocol) Explain() string {
	return ProtocolTypeDescription[what].Description
}

func (what Protocol) IsProcessLocal() bool {
	switch what {
	case InProcessLibraryCall, InterProcessCommunication, LocalFileAccess, ContainerSpawning:
		return true
	default:
		return false
	}
}

func (what Protocol) IsEncrypted() bool {
	switch what {
	case HTTPS, WSS, JdbcEncrypted, OdbcEncrypted,
		NosqlAccessProtocolEncrypted, SqlAccessProtocolEncrypted, BinaryEncrypted, TextEncrypted, SSH, SshTunnel,
		FTPS, SFTP, SCP, LDAPS, ReverseProxyWebProtocolEncrypted,
		IiopEncrypted, JrmpEncrypted, SmbEncrypted, SmtpEncrypted, Pop3Encrypted, ImapEncrypted:
		return true
	default:
		return false
	}
}

func (what Protocol) IsPotentialDatabaseAccessProtocol() bool {
	switch what {
	case JdbcEncrypted, OdbcEncrypted, NosqlAccessProtocolEncrypted, SqlAccessProtocolEncrypted,
		JDBC, ODBC, NosqlAccessProtocol, SqlAccessProtocol:
		return true
	default:
		return false
	}
}

func (what Protocol) IsPotentialLaxDatabaseAccessProtocol() bool {
	// include HTTP for REST-based NoSQL-DBs as well as unknown binary
	return what == HTTPS || what == HTTP || what == BINARY || what == BinaryEncrypted
}

func (what Protocol) IsPotentialWebAccessProtocol() bool {
	switch what {
	case HTTP, HTTPS, WS, WSS, ReverseProxyWebProtocol, ReverseProxyWebProtocolEncrypted:
		return true
	default:
		return false
	}
}

func (what Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Protocol) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Protocol) MarshalYAML() (any, error) {
	return what.String(), nil
}

func (what *Protocol) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Protocol) find(value string) (Protocol, error) {
	for index, description := range ProtocolTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Protocol(index), nil
		}
	}

	return Protocol(0), fmt.Errorf("unknown protocol value %q", value)
}
