package dhcpkea

import "encoding/json"

// Private fixed engine schema. No raw JSON, executable, path, hook, relay,
// database credentials or control-socket input is accepted from configuration.
type document struct {
	DHCP4 server `json:"Dhcp4"`
}
type server struct {
	Interfaces            interfaces    `json:"interfaces-config"`
	Database              database      `json:"lease-database"`
	HostIdentifiers       []string      `json:"host-reservation-identifiers"`
	MatchClientID         bool          `json:"match-client-id"`
	Authoritative         bool          `json:"authoritative"`
	CalculateTeeTimes     bool          `json:"calculate-tee-times"`
	ReservationsGlobal    bool          `json:"reservations-global"`
	ReservationsInSubnet  bool          `json:"reservations-in-subnet"`
	ReservationsOutOfPool bool          `json:"reservations-out-of-pool"`
	DDNS                  ddns          `json:"dhcp-ddns"`
	SendDDNS              bool          `json:"ddns-send-updates"`
	MultiThreading        threading     `json:"multi-threading"`
	Queue                 queue         `json:"dhcp-queue-control"`
	Classes               []clientClass `json:"client-classes"`
	Sanity                sanity        `json:"sanity-checks"`
	CacheThreshold        json.Number   `json:"cache-threshold"`
	StatisticSampleCount  uint32        `json:"statistic-default-sample-count"`
	Subnets               []subnet      `json:"subnet4"`
	Loggers               []logger      `json:"loggers"`
}
type interfaces struct {
	Names      []string `json:"interfaces"`
	SocketType string   `json:"dhcp-socket-type"`
	RequireAll bool     `json:"service-sockets-require-all"`
	MaxRetries uint32   `json:"service-sockets-max-retries"`
}
type database struct {
	Type         string `json:"type"`
	Persist      bool   `json:"persist"`
	Name         string `json:"name"`
	LFCInterval  uint32 `json:"lfc-interval"`
	MaxRowErrors uint32 `json:"max-row-errors"`
}
type ddns struct {
	Enabled bool `json:"enable-updates"`
}
type threading struct {
	Enabled bool `json:"enable-multi-threading"`
}
type queue struct {
	Enabled bool `json:"enable-queue"`
}
type clientClass struct {
	Name string `json:"name"`
	Test string `json:"test"`
}
type sanity struct {
	LeaseChecks string `json:"lease-checks"`
}
type subnet struct {
	ID               uint32        `json:"id"`
	Interface        string        `json:"interface"`
	Subnet           string        `json:"subnet"`
	ClientClass      string        `json:"client-class"`
	ValidLifetime    uint32        `json:"valid-lifetime"`
	MinValidLifetime uint32        `json:"min-valid-lifetime"`
	MaxValidLifetime uint32        `json:"max-valid-lifetime"`
	Renew            uint32        `json:"renew-timer"`
	Rebind           uint32        `json:"rebind-timer"`
	Pools            []pool        `json:"pools"`
	Reservations     []reservation `json:"reservations"`
	Options          []option      `json:"option-data"`
}
type pool struct {
	Range string `json:"pool"`
}
type reservation struct {
	MAC     string `json:"hw-address"`
	Address string `json:"ip-address"`
}
type option struct {
	Name string `json:"name"`
	Data string `json:"data"`
}
type logger struct {
	Name     string      `json:"name"`
	Severity string      `json:"severity"`
	Outputs  []logOutput `json:"output-options"`
}
type logOutput struct {
	Output string `json:"output"`
}
