package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	tlsRecordAlert                = 0x15
	tlsRecordHandshake            = 0x16
	tlsRecordHandshakeClientHello = 0x01
	tlsRecordHandshakeServerHello = 0x02
	tlsRecordTLS10                = 0x0301
	tlsRecordTLS11                = 0x0302
	tlsRecordTLS12                = 0x0303
)

var ciphersClients map[uint16]int
var ciphersServers map[uint16]int
var alerts map[uint16]int
var tlsVersionsClients map[uint16]int
var tlsVersionsServers map[uint16]int

type uint16IntPair struct {
	Key   uint16
	Value int
}
type uint16IntPairList []uint16IntPair

func (p uint16IntPairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p uint16IntPairList) Len() int           { return len(p) }
func (p uint16IntPairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

/*
 * Function turns map[uint16]int into sorted array
 * of key value pairs.
 */
func uint16IntPairSort(m map[uint16]int) uint16IntPairList {
	p := make(uint16IntPairList, len(m))
	i := 0
	for k, v := range m {
		p[i] = uint16IntPair{k, v}
		i++
	}
	sort.Sort(p)
	return p
}

func translateCipher(cipher uint16) string {
	if Ciphers[cipher] != "" {
		return Ciphers[cipher]
	}
	return fmt.Sprintf("[UNKNOWN CIPHER 0x%04X]", cipher)
}

func translateAlert(alert uint16) string {
	if Alerts[alert] != "" {
		return Alerts[alert]
	}
	return fmt.Sprintf("[UNKNOWN ALERT 0x%04X]", alert)
}

func translateTLSVersions(tlsversion uint16) string {
	if TLSVersions[tlsversion] != "" {
		return TLSVersions[tlsversion]
	}
	return fmt.Sprintf("[UNKNOWN TLS VERSION 0x%04X]", tlsversion)
}

/*
 * This function decodes a TCP packet
 */
func handlePacket(packet gopacket.Packet) {
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		payload := tcp.BaseLayer.Payload

		/*
		 * We are searching for a TLS record header
		 * (http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session)
		 * First byte: 0x16 for ALLPLICATION_DATA
		 * Two consecutive bytes: 0x0303 for TLS 1.2
		 */

		// Payload must be bigger than 5 bytes (TLS header is 5 bytes)
		if len(payload) >= 5 {
			// Make sure we have a TLS record here.
			if payload[0] == tlsRecordHandshake {
				// See if message type in handshake layer is TLSRecordHandshakeClientHello
				TLSRecordHandshakeMessageType := payload[5]

				/*
				 * If TLS handshake HELLO is CLIENT_HELLO
				 */
				if TLSRecordHandshakeMessageType == tlsRecordHandshakeClientHello {
					// TLS version in Handshake layer
					TLSHandshakeLayerVersion := binary.BigEndian.Uint16(payload[9:11]) // Catch two bytes and interpret as single number (0xXXXX)

					tlsVersionsClients[TLSHandshakeLayerVersion]++

					/*
					 * Get ciphers
					 */

					// After payload byte 43 there is session ID length and session ID
					// In most cases session ID length is 0x00, so there is no session ID byte.
					// Check the length of the session ID and contunie from there
					// After the session ID length and session ID bytes, the cipher part starts
					// Anatomy of th CLIENT_HELLO handshake message:
					// 	<TLS VERSION 2B> | <RANDOM 32B> | <SESS ID LENGTH 1B> | <SESS ID 0..nB> | <CIPHER SUITES LEN 2B> | <CIPHER 1 2B> | CIPHER 2 2B> | ...

					// Detect cipher block start byte
					sessionIDLength := payload[43]
					cipherSuitesStart := 43 + 1 + sessionIDLength // session length offset (43B) + length byte (1B) + sessionIDLength

					// Detect length of cipher part
					CiphersLengthBytes := binary.BigEndian.Uint16(payload[cipherSuitesStart : cipherSuitesStart+2])

					// Walk through all ciphers and count occurances
					var i uint16
					for i = 0; i < CiphersLengthBytes; i += 2 {
						cipherpos := cipherSuitesStart + 2 + byte(i)
						cipher := binary.BigEndian.Uint16(payload[cipherpos : cipherpos+2])
						ciphersClients[cipher]++ // Increment counter for this cipher
					}
				}

				/*
				 * If TLS Handshake HELLO is SERVER_HELLO
				 */
				if TLSRecordHandshakeMessageType == tlsRecordHandshakeServerHello {
					// TLS in Handshake layer
					TLSHandshakeLayerVersion := binary.BigEndian.Uint16(payload[9:11])

					tlsVersionsServers[TLSHandshakeLayerVersion]++

					// Detect cipher block start byte
					sessionIDLength := payload[43]
					cipherSuitesStart := 43 + 1 + sessionIDLength // session length offset (43B) + length byte (1B) + sessionIDLength

					// Detect length of cipher part
					// (Not needed for server part, because only one cipher is suggested by server)

					// Walk through all ciphers and count occurances
					// (no walking needed, because there is only one cipher suggested)
					cipherpos := cipherSuitesStart
					cipher := binary.BigEndian.Uint16(payload[cipherpos : cipherpos+2])
					ciphersServers[cipher]++ // Increment counter for this cipher

				}
			} else if payload[0] == tlsRecordAlert {
				/*
				 * If there is an alert message
				 * Search for any Handshake failures
				 */
				tlsAlertLength := binary.BigEndian.Uint16(payload[3:5])
				// Alerts need to have length 2 bytes
				if tlsAlertLength == 2 {
					tlsAlertDescription := payload[6]
					alerts[uint16(tlsAlertDescription)]++
				}
			}
		}
	}
}

func main() {
	var pkgctr int64
	ciphersClients = make(map[uint16]int)
	ciphersServers = make(map[uint16]int)
	tlsVersionsClients = make(map[uint16]int)
	tlsVersionsServers = make(map[uint16]int)
	alerts = make(map[uint16]int)

	// Get pcap file flag
	var argPcapFile = flag.String("d", "tcpdump.pcap", "Path to .pcap file.")
	flag.Parse()

	tab := new(tabwriter.Writer)
	tab.Init(os.Stdout, 5, 4, 2, ' ', 0)

	if handle, err := pcap.OpenOffline(*argPcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			handlePacket(packet) // Do something with a packet here.
			pkgctr++
		}
	}

	fmt.Printf("%d packets analyzed. Here are the results:\n\n", pkgctr)

	/*
	 * Show TLS versions
	 */
	// Client TLS versions (available)
	fmt.Println("=== TLS versions supported by clients ===")
	tlsVersionsClientsSorted := uint16IntPairSort(tlsVersionsClients)
	for _, tlsversionPair := range tlsVersionsClientsSorted {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateTLSVersions(tlsversionPair.Key), tlsversionPair.Value)
	}
	tab.Flush() // Write table

	fmt.Println()

	// Server TLS versions
	fmt.Println("=== TLS versions chosen by server ===")
	tlsVersionsServersSorted := uint16IntPairSort(tlsVersionsServers)
	for _, tlsversionPair := range tlsVersionsServersSorted {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateTLSVersions(tlsversionPair.Key), tlsversionPair.Value)
	}
	tab.Flush() // Write table

	fmt.Println()

	/*
	 *  Show offered / used ciphers
	 */
	// Client ciphers (available)
	fmt.Println("=== Ciphers supported by clients: ===")
	ciphersClientsSorted := uint16IntPairSort(ciphersClients)
	for _, cipherPair := range ciphersClientsSorted {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateCipher(cipherPair.Key), cipherPair.Value)
	}
	tab.Flush() // Write table

	fmt.Println()

	// Server ciphers (chosen)
	fmt.Println("=== Ciphers chosen by server ===")
	ciphersServersSorted := uint16IntPairSort(ciphersServers)
	for _, cipherPair := range ciphersServersSorted {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateCipher(cipherPair.Key), cipherPair.Value)
	}

	tab.Flush() // Write table

	fmt.Println()

	/*
	 * Show errors (TLS alerts)
	 */

	fmt.Println("=== TLS alerts ===")
	alertsSorted := uint16IntPairSort(alerts)
	for _, alertPair := range alertsSorted {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateAlert(alertPair.Key), alertPair.Value)
	}
	tab.Flush()
}
