package server

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/fisker/zvpn/vpn/util"
)

// WriteLoop handles writing packets to the client connection in a separate goroutine
// This ensures writes don't interfere with reads
// If write batching is enabled, it collects multiple packets and writes them in batches
func (c *VPNClient) WriteLoop() {
	defer func() {
		// 检查是否是正常关闭（WriteClose channel 已关闭）
		select {
		case <-c.WriteClose:
			// WriteClose 已关闭，这是正常的关闭流程
			log.Printf("Write loop for client %d (IP: %s) stopped (normal shutdown)", c.UserID, c.IP.String())
		default:
			// WriteClose 未关闭，可能是异常退出（如 channel 关闭或错误）
			log.Printf("Write loop for client %d (IP: %s) stopped (unexpected exit - check for errors above)", c.UserID, c.IP.String())
		}
	}()

	// Get config from server if available
	var enableBatching bool
	var batchSize int
	var batchTimeout time.Duration

	if c.server != nil && c.server.config != nil {
		enableBatching = c.server.config.VPN.EnableWriteBatching
		batchSize = c.server.config.VPN.WriteBatchSize
		batchTimeout = time.Duration(c.server.config.VPN.WriteBatchTimeout) * time.Millisecond
	} else {
		// Defaults: Disable batching by default to ensure CSTP packet boundaries
		// Batching can cause "Unknown packet received" errors with OpenConnect clients
		enableBatching = false
		batchSize = 1 // Process one packet at a time
		batchTimeout = 0 * time.Millisecond
	}

	// IMPORTANT: For CSTP protocol compatibility, disable batching if not explicitly enabled
	// Batching can cause packet boundary issues where multiple CSTP packets are merged
	// into a single TCP segment, causing OpenConnect clients to fail parsing.
	if !enableBatching {
		// Force single packet mode
		batchSize = 1
		batchTimeout = 0
	}

	// Validate batch size and timeout
	if batchSize <= 0 {
		batchSize = 10
	}
	if batchTimeout <= 0 {
		batchTimeout = 1 * time.Millisecond
	}

	if enableBatching {
		c.writeLoopBatched(batchSize, batchTimeout)
	} else {
		c.writeLoopSingle()
	}
}

// writeLoopSingle handles single packet writes (original behavior)
func (c *VPNClient) writeLoopSingle() {
	for {
		select {
		case packet, ok := <-c.WriteChan:
			if !ok {
				log.Printf("Write loop stopping for client %d (IP: %s): WriteChan closed (normal shutdown)", c.UserID, c.IP.String())
				return
			}
			// Check if connection is closing before processing packet
			select {
			case <-c.WriteClose:
				log.Printf("Write loop stopping for client %d (IP: %s): WriteClose signal received (normal shutdown)", c.UserID, c.IP.String())
				return
			default:
				c.writePacket(packet)
			}

		case <-c.WriteClose:
			log.Printf("Write loop stopping for client %d (IP: %s): WriteClose signal received (normal shutdown)", c.UserID, c.IP.String())
			return
		}
	}
}

// writeLoopBatched handles batched packet writes for better performance
func (c *VPNClient) writeLoopBatched(batchSize int, batchTimeout time.Duration) {
	batch := make([][]byte, 0, batchSize)
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case packet, ok := <-c.WriteChan:
			if !ok {
				// Channel closed, flush any remaining packets
				if len(batch) > 0 {
					c.writeBatch(batch)
				}
				log.Printf("Write loop stopping for client %d (IP: %s): WriteChan closed (normal shutdown)", c.UserID, c.IP.String())
				return
			}

			batch = append(batch, packet)

			// Flush if batch is full
			if len(batch) >= batchSize {
				c.writeBatch(batch)
				batch = batch[:0] // Reset batch
			}

		case <-ticker.C:
			// Timeout: flush any accumulated packets
			if len(batch) > 0 {
				c.writeBatch(batch)
				batch = batch[:0] // Reset batch
			}

		case <-c.WriteClose:
			// Stop signal: don't flush remaining packets if connection is closing
			// Flushing would cause RST if client already sent FIN
			log.Printf("Write loop stopping for client %d (IP: %s): WriteClose signal received (normal shutdown, dropping %d queued packets)",
				c.UserID, c.IP.String(), len(batch))
			return
		}
	}
}

// writePacket writes a single packet to the connection
func (c *VPNClient) writePacket(packet []byte) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	// Check if connection is closing before attempting write
	select {
	case <-c.WriteClose:
		// Connection is closing, don't write
		log.Printf("Skipping write to client %d (IP: %s): connection is closing", c.UserID, c.IP.String())
		return
	default:
		// Connection is still open, proceed with write
	}

	// Log packet details before writing (for debugging CSTP issues)
	// Check if packet has STF prefix (server-to-client packets now include STF prefix)
	if len(packet) >= 8 && packet[0] == 'S' && packet[1] == 'T' && packet[2] == 'F' {
		// Packet has STF prefix, CSTP header starts at offset 3
		// Format per BuildCSTPPacket: STF(3) + Version(1) + Length(2) + Type(1) + Reserved(1) + Payload
		// Byte 0-2: STF
		// Byte 3: Version (0x01)
		// Byte 4-5: Length (BIG-ENDIAN) - payload length only, NOT including header
		// Byte 6: Type (0x00)
		// Byte 7: Reserved (0x00)
		// Byte 8+: Payload
		payloadLength := binary.BigEndian.Uint16(packet[4:6]) // Length at byte 4-5
		// Total packet = STF(3) + Header(5) + Payload = 8 + payloadLength
		expectedTotalSize := 8 + int(payloadLength)

		// Verify CSTP length field matches expected size
		if expectedTotalSize != len(packet) {
			log.Printf("ERROR: CSTP length field mismatch! Header says payload is %d bytes (BIG-ENDIAN at byte 4-5), expected total %d bytes (8 header + %d payload), but packet is %d bytes. This will cause client parsing errors!",
				payloadLength, expectedTotalSize, payloadLength, len(packet))
		}
	}

	// CRITICAL: Separate TCP and DTLS usage:
	// - Data packets (PacketTypeData, 0x00) should use DTLS if available, otherwise TCP
	// - Control packets (keepalive, DPD, etc.) should always use TCP (per OpenConnect spec)
	//
	// DTLS format: first byte is packet type, then payload
	// - 0x00 = DATA (IP packet)
	// - 0x03 = DPD-REQ
	// - 0x04 = DPD-RESP
	// - 0x05 = DISCONNECT
	// - 0x07 = KEEPALIVE
	// - 0x08 = COMPRESSED DATA
	conn := c.Conn // Default to TCP
	connType := "TCP"
	var writePacket []byte // Packet to write

	// Check if this is a data packet (PacketTypeData = 0x00)
	// Data packets should use DTLS if available
	if len(packet) >= 8 && packet[0] == 'S' && packet[1] == 'T' && packet[2] == 'F' {
		// Packet has STF prefix, check packet type at byte 6
		packetType := packet[6]
		if packetType == 0x00 && c.DTLSConn != nil {
			// Data packet: use DTLS if available
			// DTLS format: first byte is packet type (0x00), then IP packet
			conn = c.DTLSConn
			connType = "DTLS"
			// Build DTLS packet: packet type (1 byte) + payload
			payload := packet[8:] // Skip STF(3) + Header(5) = 8 bytes
			dtlsPacket := make([]byte, 1+len(payload))
			dtlsPacket[0] = packetType // 0x00 = DATA
			copy(dtlsPacket[1:], payload)
			writePacket = dtlsPacket
		} else {
			// Control packet: always use TCP (per OpenConnect spec)
			conn = c.Conn
			connType = "TCP"
			writePacket = packet
		}
	} else if c.DTLSConn != nil {
		// Legacy format or unknown format: if DTLS available, try DTLS first
		conn = c.DTLSConn
		connType = "DTLS"
		writePacket = packet
	} else {
		writePacket = packet
	}

	written := 0
	for written < len(writePacket) {
		n, err := conn.Write(writePacket[written:])
		if err != nil {
			log.Printf("Failed to write packet to client %d (IP: %s) via %s: %v (wrote %d/%d bytes) - connection may be closed",
				c.UserID, c.IP.String(), connType, err, written, len(packet))

			// If DTLS write failed, fallback to TCP for data packets
			if connType == "DTLS" && len(packet) >= 8 && packet[6] == 0x00 {
				log.Printf("DTLS write failed for user %d (IP: %s), automatically falling back to CSTP (TCP) only mode - clearing DTLS connection",
					c.UserID, c.IP.String())
				c.DTLSConn = nil
				conn = c.Conn
				connType = "TCP"
				writePacket = packet
				written = 0
				continue
			}

			select {
			case <-c.WriteClose:
			default:
				close(c.WriteClose)
			}
			return
		}
		written += n
	}

	// CRITICAL: Ensure TCP buffer is flushed immediately after writing
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		time.Sleep(10 * time.Millisecond)
		if err := tcpConn.SetWriteDeadline(time.Now().Add(1 * time.Millisecond)); err == nil {
			tcpConn.SetWriteDeadline(time.Time{})
		}
	}

	if written != len(writePacket) {
		log.Printf("Warning: Incomplete write to client %d (IP: %s): wrote %d/%d bytes",
			c.UserID, c.IP.String(), written, len(writePacket))
	}
}

// writeBatch writes multiple packets in a batch using writev-like approach
func (c *VPNClient) writeBatch(batch [][]byte) {
	if len(batch) == 0 {
		return
	}

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	for _, packet := range batch {
		select {
		case <-c.WriteClose:
			log.Printf("Stopping batch write to client %d (IP: %s): connection is closing", c.UserID, c.IP.String())
			return
		default:
		}

		if len(packet) >= 8 && packet[0] == 'S' && packet[1] == 'T' && packet[2] == 'F' {
			payloadLength := binary.BigEndian.Uint16(packet[4:6])
			expectedTotalSize := 8 + int(payloadLength)
			if expectedTotalSize != len(packet) {
				log.Printf("ERROR: CSTP length field mismatch in batch! Header says payload is %d bytes (BIG-ENDIAN at byte 4-5), expected total %d bytes (8 header + %d payload), but packet is %d bytes. This will cause client parsing errors!",
					payloadLength, expectedTotalSize, payloadLength, len(packet))
			}
		}

		conn := c.Conn
		connType := "TCP"
		var writePacket []byte

		if len(packet) >= 8 && packet[0] == 'S' && packet[1] == 'T' && packet[2] == 'F' {
			packetType := packet[6]
			if packetType == 0x00 && c.DTLSConn != nil {
				conn = c.DTLSConn
				connType = "DTLS"
				payload := packet[8:]
				dtlsPacket := make([]byte, 1+len(payload))
				dtlsPacket[0] = packetType
				copy(dtlsPacket[1:], payload)
				writePacket = dtlsPacket
			} else {
				conn = c.Conn
				connType = "TCP"
				writePacket = packet
			}
		} else if c.DTLSConn != nil {
			conn = c.DTLSConn
			connType = "DTLS"
			writePacket = packet
		} else {
			writePacket = packet
		}

		written := 0
		for written < len(writePacket) {
			n, err := conn.Write(writePacket[written:])
			if err != nil {
				log.Printf("Failed to write batch packet to client %d (IP: %s) via %s: %v (wrote %d/%d bytes) - connection may be closed",
					c.UserID, c.IP.String(), connType, err, written, len(packet))

				if connType == "DTLS" && len(packet) >= 8 && packet[6] == 0x00 {
					log.Printf("DTLS write failed for user %d (IP: %s) in batch, automatically falling back to CSTP (TCP) only mode - clearing DTLS connection",
						c.UserID, c.IP.String())
					c.DTLSConn = nil
					conn = c.Conn
					connType = "TCP"
					writePacket = packet
					written = 0
					continue
				}

				select {
				case <-c.WriteClose:
				default:
					close(c.WriteClose)
				}
				return
			}
			written += n
		}

		if _, ok := conn.(*net.TCPConn); ok {
			time.Sleep(5 * time.Millisecond)
		}

		if written != len(packet) {
			log.Printf("Warning: Incomplete batch write to client %d (IP: %s): wrote %d/%d bytes",
				c.UserID, c.IP.String(), written, len(packet))
		}
	}

	if len(batch) > 0 {
		totalBytes := 0
		for _, p := range batch {
			totalBytes += len(p)
		}
		util.LogPacket("Successfully wrote batch of %d packets (%d bytes) to client %d (IP: %s)",
			len(batch), totalBytes, c.UserID, c.IP.String())
	}
}
