package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
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
var alerts map[byte]int
var tlsVersionsClients map[uint16]int
var tlsVersionsServers map[uint16]int

func translateCipher(cipher uint16) string {
	if Ciphers[cipher] != "" {
		return Ciphers[cipher]
	}
	return fmt.Sprintf("[UNKNOWN CIPHER 0x%04X]", cipher)
}

func translateAlert(alert byte) string {
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

				// Make sure to only consider Handshake_CLIENT_HELLO messages at the end of TLS negotiation (in handshake layer)
				// Find out where handshake layer starts. Length in TLS record layer tells us
				// where record layer ends and where handshake layer starts
				//TLSHeaderLength := binary.BigEndian.Uint16(payload[3:5])
				//fmt.Println("TLS Record header length:", TLSHeaderLength)

				// See if message type in handshake layer is TLSRecordHandshakeClientHello
				TLSRecordHandshakeMessageType := payload[5]

				if TLSRecordHandshakeMessageType == tlsRecordHandshakeClientHello {
					// TLS in Handshake layer
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
					alerts[tlsAlertDescription]++
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
	alerts = make(map[byte]int)

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

	fmt.Printf("\n\n%d packets analyzed. Here are the results:\n\n", pkgctr)

	/*
	 * Show TLS versions
	 */
	// Client TLS versions (available)
	fmt.Println("=== TLS versions supported by clients ===")
	for tlsversion := range tlsVersionsClients {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateTLSVersions(tlsversion), tlsVersionsClients[tlsversion])
	}
	tab.Flush() // Write table

	fmt.Println()

	// Server TLS versions
	fmt.Println("=== TLS versions chosen by server ===")
	for tlsversion := range tlsVersionsServers {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateTLSVersions(tlsversion), tlsVersionsServers[tlsversion])
	}
	tab.Flush() // Write table

	fmt.Println()

	/*
	 *  Show offered / used ciphers
	 */
	// Client ciphers (available)
	fmt.Println("=== Ciphers supported by clients: ===")
	for cipher := range ciphersClients {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateCipher(cipher), ciphersClients[cipher])
	}
	tab.Flush() // Write table

	fmt.Println()

	// Server ciphers (chosen)
	fmt.Println("=== Ciphers chosen by server: ===")
	for cipher := range ciphersServers {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateCipher(cipher), ciphersServers[cipher])
	}
	tab.Flush() // Write table

	fmt.Println()

	/*
	 * Show errors (TLS alerts)
	 */

	fmt.Println("=== TLS alerts ===")
	for alert := range alerts {
		fmt.Fprintf(tab, "%s\t\t%d\n", translateAlert(alert), alerts[alert])
	}
	tab.Flush()
}
