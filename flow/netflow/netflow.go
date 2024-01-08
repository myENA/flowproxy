package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/myENA/flowproxy/common"
	"golang.org/x/time/rate"
	"net"
	"strconv"
	"time"
)

// Constants for ports
const (
	ftpPort      = 21
	sshPort      = 22
	dnsPort      = 53
	httpPort     = 80
	httpsPort    = 443
	ntpPort      = 123
	snmpPort     = 161
	imapsPort    = 993
	mysqlPort    = 3306
	httpAltPort  = 8080
	httpsAltPort = 8443
	p2pPort      = 6681
	btPort       = 6682
)

// Constants for protocols
const (
	tcpProto   = 6
	udpProto   = 17
	icmpProto  = 1
	sctpProto  = 132
	igmpProto  = 2
	egpProto   = 8
	igpProto   = 9
	greProto   = 47
	espProto   = 50
	eigrpProto = 88
)

// Constants for Field Types
const (
	IN_BYTES                     = 1
	IN_PKTS                      = 2
	FLOWS                        = 3
	PROTOCOL                     = 4
	SRC_TOS                      = 5
	TCP_FLAGS                    = 6
	L4_SRC_PORT                  = 7
	IPV4_SRC_ADDR                = 8
	SRC_MASK                     = 9
	INPUT_SNMP                   = 10
	L4_DST_PORT                  = 11
	IPV4_DST_ADDR                = 12
	DST_MASK                     = 13
	OUTPUT_SNMP                  = 14
	IPV4_NEXT_HOP                = 15
	SRC_AS                       = 16
	DST_AS                       = 17
	BGP_IPV4_NEXT_HOP            = 18
	MUL_DST_PKTS                 = 19
	MUL_DST_BYTES                = 20
	LAST_SWITCHED                = 21
	FIRST_SWITCHED               = 22
	OUT_BYTES                    = 23
	OUT_PKTS                     = 24
	MIN_PKT_LNGTH                = 25
	MAX_PKT_LNGTH                = 26
	IPV6_SRC_ADDR                = 27
	IPV6_DST_ADDR                = 28
	IPV6_SRC_MASK                = 29
	IPV6_DST_MASK                = 30
	IPV6_FLOW_LABEL              = 31
	ICMP_TYPE                    = 32
	MUL_IGMP_TYPE                = 33
	SAMPLING_INTERVAL            = 34
	SAMPLING_ALGORITHM           = 35
	FLOW_ACTIVE_TIMEOUT          = 36
	FLOW_INACTIVE_TIMEOUT        = 37
	ENGINE_TYPE                  = 38
	ENGINE_ID                    = 39
	TOTAL_BYTES_EXP              = 40
	TOTAL_PKTS_EXP               = 41
	TOTAL_FLOWS_EXP              = 42
	IPV4_SRC_PREFIX              = 44
	IPV4_DST_PREFIX              = 45
	MPLS_TOP_LABEL_TYPE          = 46
	MPLS_TOP_LABEL_IP_ADDR       = 47
	FLOW_SAMPLER_ID              = 48
	FLOW_SAMPLER_MODE            = 49
	FLOW_SAMPLER_RANDOM_INTERVAL = 50
	MIN_TTL                      = 52
	MAX_TTL                      = 53
	IPV4_IDENT                   = 54
	DST_TOS                      = 55
	IN_SRC_MAC                   = 56
	OUT_DST_MAC                  = 57
	SRC_VLAN                     = 58
	DST_VLAN                     = 59
	IP_PROTOCOL_VERSION          = 60
	DIRECTION                    = 61
	IPV6_NEXT_HOP                = 62
	BGP_IPV6_NEXT_HOP            = 63
	IPV6_OPTION_HEADERS          = 64
	MPLS_LABEL_1                 = 70
	MPLS_LABEL_2                 = 71
	MPLS_LABEL_3                 = 72
	MPLS_LABEL_4                 = 73
	MPLS_LABEL_5                 = 74
	MPLS_LABEL_6                 = 75
	MPLS_LABEL_7                 = 76
	MPLS_LABEL_8                 = 77
	MPLS_LABEL_9                 = 78
	MPLS_LABEL_10                = 79
	IN_DST_MAC                   = 80
	OUT_SRC_MAC                  = 81
	IF_NAME                      = 82
	IF_DESC                      = 83
	SAMPLER_NAME                 = 84
	IN_PERMANENT_BYTES           = 85
	IN_PERMANENT_PKTS            = 86
	FRAGMENT_OFFSET              = 88
	FORWARDING_STATUS            = 89
	MPLS_PAL_RD                  = 90
	MPLS_PREFIX_LEN              = 91
	SRC_TRAFFIC_INDEX            = 92
	DST_TRAFFIC_INDEX            = 93
	APPLICATION_DESCRIPTION      = 94
	APPLICATION_TAG              = 95
	APPLICATION_NAME             = 96
	postipDiffServCodePoint      = 98
	replication_factor           = 99
	layer2packetSectionOffset    = 102
	layer2packetSectionSize      = 103
	layer2packetSectionData      = 104
)

// FlowPacket Top level struct for the whole v9 flow packet
type FlowPacket struct {
	Header
	Flows []FlowSet
}

// Header NetflowHeader v9
type Header struct {
	Version      uint16 `json:"version,omitempty"`
	FlowCount    uint16 `json:"flowCount,omitempty"`
	SysUptime    uint32 `json:"sysUptime,omitempty"`
	UnixSec      uint32 `json:"unixSec,omitempty"`
	FlowSequence uint32 `json:"flowSequence,omitempty"`
	SourceID     uint32 `json:"sourceID,omitempty"`
}

// Get the size of the Header in bytes
func (h *Header) size() int {
	size := binary.Size(h.Version)
	size += binary.Size(h.FlowCount)
	size += binary.Size(h.SysUptime)
	size += binary.Size(h.UnixSec)
	size += binary.Size(h.FlowSequence)
	size += binary.Size(h.SourceID)
	return size
}

// Get the Header in String
func (h *Header) String() string {
	return "Version: " + strconv.Itoa(int(h.Version)) +
		" Count: " + strconv.Itoa(int(h.FlowCount)) +
		" SysUptime: " + strconv.Itoa(int(h.SysUptime)) +
		" UnixSec: " + strconv.Itoa(int(h.UnixSec)) +
		" FlowSequence: " + strconv.Itoa(int(h.FlowSequence)) +
		" SourceID: " + strconv.Itoa(int(h.SourceID)) +
		" || "
}

// Field for OptionTemplate and Template struct
type Field struct {
	Type   uint16 `json:"type,omitempty"`
	Length uint16 `json:"length,omitempty"`
}

// Get the Field in String
func (f *Field) String() string {
	return "Type: " + strconv.Itoa(int(f.Type)) + "Length: " + strconv.Itoa(int(f.Length))
}

// OptionTemplate for OptionFlowSet
type OptionTemplate struct {
	TemplateID        uint16  `json:"templateID,omitempty"`
	OptionScopeLength uint16  `json:"optionScopeLength,omitempty"`
	OptionLength      uint16  `json:"optionLength,omitempty"`
	Scopes            []Field `json:"scopes,omitempty"`
	Options           []Field `json:"options,omitempty"`
}

// Template for TemplateFlowSet
type Template struct {
	TemplateID uint16  `json:"templateID,omitempty"` // 0-255
	FieldCount uint16  `json:"fieldCount,omitempty"`
	Fields     []Field `json:"fields,omitempty"`
}

// FlowSet for Netflow
type FlowSet struct {
	ID     uint16        `json:"ID,omitempty"`     // 0 for Template, 1 Options, > 256 Data
	Length uint16        `json:"length,omitempty"` // total length in byte, padding included.
	Flows  []interface{} `json:"flows,omitempty"`
}

type DeviceManager struct {
	Devices       map[string]DeviceDetails `json:"devices,omitempty"`
	DeviceCounter int                      `json:"deviceCounter"`
}

type DeviceDetails struct {
	ID              int             `json:"ID,omitempty"`
	Created         time.Time       `json:"created"`
	Updated         time.Time       `json:"updated"`
	IP              net.IP          `json:"IP,omitempty"`
	SampleRate      int             `json:"sampleRate,omitempty"`
	TemplateManager TemplateManager `json:"templateManager"`
	Stats           DeviceStats     `json:"stats"`
	Limiter         *rate.Limiter
}

type DeviceStats struct {
	Pkts         uint64 `json:"pkts,omitempty"`
	DataSent     uint64 `json:"dataSent,omitempty"`
	TemplateSent uint64 `json:"templateSent,omitempty"`
	OptionSent   uint64 `json:"optionSent,omitempty"`
}

type TemplateDetails struct {
	Created time.Time   `json:"created"`
	Updated time.Time   `json:"updated"`
	Types   map[int]int `json:"types,omitempty"` //field ID, field Length
}

type OptionTemplateDetails struct {
	Created time.Time   `json:"created"`
	Updated time.Time   `json:"updated"`
	Options map[int]int `json:"options,omitempty"` // field type ID, field Length
	Scopes  map[int]int `json:"scopes,omitempty"`  // field type ID, field Length
}

func (dm *DeviceManager) Init() DeviceManager {
	deviceManager := new(DeviceManager)
	deviceManager.DeviceCounter = 0
	deviceManager.Devices = make(map[string]DeviceDetails)
	return *deviceManager
}

func (dm *DeviceManager) AddDevice(ip string) {
	dm.DeviceCounter++
	deviceDetails := DeviceDetails{
		ID:              dm.DeviceCounter,
		Created:         time.Now(),
		Updated:         time.Now(),
		IP:              net.ParseIP(ip),
		SampleRate:      0,
		TemplateManager: new(TemplateManager).Init(),
		Stats: DeviceStats{
			Pkts:         0,
			DataSent:     0,
			TemplateSent: 0,
			OptionSent:   0,
		},
	}
	dm.Devices[ip] = deviceDetails
}

func (dm *DeviceManager) SetSampleRate(ip string, rateNum int) {
	details := dm.GetDevice(ip)
	// details.Limiter = rate.NewLimiter(rate.Every(time.Second/time.Duration(rateNum)), rateNum+(rateNum+5)/10)
	details.Limiter = rate.NewLimiter(rate.Every(time.Second/time.Duration(rateNum)), rateNum)
	details.SampleRate = rateNum
	dm.UpdateDevice(ip, details)
}

func (dm *DeviceManager) CheckSampleRate(ip string, dataCount int) bool {
	details := dm.GetDevice(ip)
	limiter := details.Limiter
	if limiter.AllowN(time.Now(), dataCount) {
		return true
	}
	return false
}

func (dm *DeviceManager) LookupDevice(ip string) bool {
	if _, ok := dm.Devices[ip]; ok {
		return true
	} else {
		return false
	}
}

func (dm *DeviceManager) GetDevice(ip string) DeviceDetails {
	return dm.Devices[ip]
}

func (dm *DeviceManager) UpdateDevice(ip string, details DeviceDetails) {
	dm.Devices[ip] = details
}

func (dm *DeviceManager) SeenDevice(ip string) {
	details := dm.GetDevice(ip)
	details.Updated = time.Now()
	dm.UpdateDevice(ip, details)
}

func (dm *DeviceManager) UpdateStats(ip string, dataCount uint64, templateCount uint64, optionCount uint64) {
	details := dm.GetDevice(ip)
	stats := details.Stats
	stats.Pkts++
	stats.DataSent = stats.DataSent + dataCount
	stats.TemplateSent = stats.TemplateSent + templateCount
	stats.OptionSent = stats.OptionSent + optionCount
	details.Stats = stats
	dm.UpdateDevice(ip, details)
}

func (dm *DeviceManager) GetTemplateManager(ip string) TemplateManager {
	return dm.Devices[ip].TemplateManager
}

type TemplateManager struct {
	Templates       map[int]TemplateDetails       `json:"templates,omitempty"`
	OptionTemplates map[int]OptionTemplateDetails `json:"optionTemplates,omitempty"`
}

func (tm *TemplateManager) Init() TemplateManager {
	templateManager := new(TemplateManager)
	templateManager.Templates = make(map[int]TemplateDetails)
	templateManager.OptionTemplates = make(map[int]OptionTemplateDetails)
	return *templateManager
}

func (tm *TemplateManager) LookupTemplate(id int) bool {
	if _, ok := tm.Templates[id]; ok {
		return true
	} else {
		return false
	}
}

func (tm *TemplateManager) AddTemplate(id int, types map[int]int) {
	td := TemplateDetails{
		Created: time.Now(),
		Updated: time.Now(),
		Types:   types,
	}
	tm.Templates[id] = td
}

func (tm *TemplateManager) GetTemplate(id int) TemplateDetails {
	return tm.Templates[id]
}

func (tm *TemplateManager) UpdateTemplate(id int, details TemplateDetails) {
	tm.Templates[id] = details
}

func (tm *TemplateManager) SeenTemplate(id int, types map[int]int) {
	td := tm.GetTemplate(id)
	td.Updated = time.Now()
	td.Types = types
	tm.UpdateTemplate(id, td)
}

func (tm *TemplateManager) LookupOptionTemplate(id int) bool {
	if _, ok := tm.OptionTemplates[id]; ok {
		return true
	} else {
		return false
	}
}

func (tm *TemplateManager) AddOptionTemplate(id int, options map[int]int, scopes map[int]int) {
	od := OptionTemplateDetails{
		Created: time.Now(),
		Updated: time.Now(),
		Options: options,
		Scopes:  scopes,
	}
	tm.OptionTemplates[id] = od
}

func (tm *TemplateManager) GetOptionTemplate(id int) OptionTemplateDetails {
	return tm.OptionTemplates[id]
}

func (tm *TemplateManager) UpdateOptionTemplate(id int, details OptionTemplateDetails) {
	tm.OptionTemplates[id] = details
}

func (tm *TemplateManager) SeenOptionTemplate(id int, options map[int]int, scopes map[int]int) {
	od := tm.GetOptionTemplate(id)
	od.Updated = time.Now()
	od.Options = options
	od.Scopes = scopes
	tm.UpdateOptionTemplate(id, od)
}

// IsValidNetFlow validates that the given payload has a netflow v9 header
func IsValidNetFlow(payload []byte, nfVersion int) (bool, error) {
	// yes = true, no = false
	header := Header{}
	reader := bytes.NewReader(payload)
	// Parse Netflow Header
	err := common.BinaryReader(reader, &header)
	if err != nil {
		return false, err
	}
	if header.Version != uint16(nfVersion) {
		return false, fmt.Errorf("Header version doesn't match!  Got %d and expected %d", header.Version, nfVersion)
	}
	return true, nil
}

func ParseTemplate(reader *bytes.Reader) (t Template, e error) {
	template := Template{}
	// Get static OptionsTemplateFields
	err := common.BinaryReader(reader, &template.TemplateID, &template.FieldCount)
	if err != nil {
		return template, err
	}
	// Loop through and get all the fields for template
	fieldCount := int(template.FieldCount)
	fields := make([]Field, fieldCount)
	// Get scope fields
	for f := 0; f < fieldCount; f++ {
		field := Field{}
		err = common.BinaryReader(reader, &field)
		if err != nil {
			return template, err
		}
		fields[f] = field
	}
	template.Fields = fields
	// Everything is done!
	return template, nil
}

func ParseOptionTemplate(reader *bytes.Reader) (ot OptionTemplate, e error) {
	optionTemplate := OptionTemplate{}
	// Get static OptionsTemplateFields
	err := common.BinaryReader(reader, &optionTemplate.TemplateID, &optionTemplate.OptionLength,
		&optionTemplate.OptionScopeLength)
	if err != nil {
		return optionTemplate, err
	}
	// Loop through and get all the fields for scope and options
	// Dividing by 4 because a field is composed of 2 uint16 values or 4 bytes
	scopeCount := int(optionTemplate.OptionScopeLength) / 4
	scopeFields := make([]Field, scopeCount)
	// Get scope fields
	for s := 0; s < scopeCount; s++ {
		field := Field{}
		err = common.BinaryReader(reader, &field)
		if err != nil {
			return optionTemplate, err
		}
		scopeFields[s] = field
	}
	optionTemplate.Scopes = scopeFields
	// Dividing by 4 because a field is composed of 2 uint16 values or 4 bytes
	optionCount := int(optionTemplate.OptionLength) / 4 // Dividing by 4 because a field is composed of 2 uint16 values or 4 bytes
	optionFields := make([]Field, optionCount)
	// Get option fields
	for o := 0; o < optionCount; o++ {
		field := Field{}
		err = common.BinaryReader(reader, &field)
		if err != nil {
			return optionTemplate, err
		}
		optionFields[o] = field
	}
	// Everything is done!
	return optionTemplate, nil
}

func InspectFlowPacket(payload []byte, templateManager *TemplateManager) (data uint64, template uint64, option uint64, e error) {
	var (
		dataCount     uint64 = 0
		templateCount uint64 = 0
		optionCount   uint64 = 0
		err           error
		flowPacket    FlowPacket
	)
	header := Header{}
	reader := bytes.NewReader(payload)
	err = binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return dataCount, templateCount, optionCount, err
	}
	flowPacket.Header = header
	for i := 1; i <= int(header.FlowCount); i++ {
		flow := FlowSet{}
		readerStart := reader.Len()
		err = common.BinaryReader(reader, &flow.ID, &flow.Length)
		if err != nil {
			fmt.Printf("Error decoding FlowSet: %s\n", err)
			return dataCount, templateCount, optionCount, err
		}
		switch setType := flow.ID; {
		case setType == 0:
			templateCount++
			templateFlow, err := ParseTemplate(reader)
			if err != nil {
				fmt.Printf("Error decoding Template: %s\n", err)
				fmt.Println(templateFlow)
				return dataCount, templateCount, optionCount, err
			}
			tpID := int(templateFlow.TemplateID)
			flow.Flows = append(flow.Flows, templateFlow)
			types := make(map[int]int)
			for t := 0; t < int(templateFlow.FieldCount); t++ {
				f := templateFlow.Fields[t]
				types[int(f.Type)] = int(f.Length)
			}
			// Check if template exists and update it.  If not, add it
			if templateManager.LookupTemplate(tpID) {
				templateManager.SeenTemplate(tpID, types)
			} else {
				templateManager.AddTemplate(tpID, types)
			}

		case setType == 1:
			optionCount++
			optionTemplate, err := ParseOptionTemplate(reader)
			if err != nil {
				fmt.Printf("Error decoding Option Template: %s\n", err)
				fmt.Println(optionTemplate)
				return dataCount, templateCount, optionCount, err
			}
			oID := int(optionTemplate.TemplateID)
			flow.Flows = append(flow.Flows, optionTemplate)
			options := make(map[int]int)
			scopes := make(map[int]int)
			for o := 0; o < len(optionTemplate.Options); o++ {
				f := optionTemplate.Options[o]
				options[int(f.Type)] = int(f.Length)
			}
			for s := 0; s < len(optionTemplate.Scopes); s++ {
				f := optionTemplate.Scopes[s]
				scopes[int(f.Type)] = int(f.Length)
			}
			// Check if Option Template exists and update it.  If not, add it
			if templateManager.LookupOptionTemplate(oID) {
				templateManager.SeenOptionTemplate(oID, options, scopes)
			} else {
				templateManager.AddOptionTemplate(oID, options, scopes)
			}
		case setType >= 256:
			dataCount++
		}
		// Add flowset to Packet
		flowPacket.Flows = append(flowPacket.Flows, flow)
		// Skip remaining bytes in the flowset, should be padding or at least data we don't care about.
		readerStop := reader.Len()
		bytesRead := readerStart - readerStop
		if bytesRead > 0 {
			skipCount := int(flow.Length) - bytesRead
			if skipCount > 0 {
				reader.Seek(int64(skipCount), 1)
				if err != nil {
					fmt.Printf("Error skipping bytes: %s\n", err)
				}
			}
		}
	}

	// Look here!  A flow packet!
	if err != nil {
		fmt.Println(flowPacket)
	}
	return dataCount, templateCount, optionCount, nil
}
