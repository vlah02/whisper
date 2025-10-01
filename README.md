# Whisper - Advanced P2P Chat Network

A sophisticated peer-to-peer chat application built with Go, WebRTC, and WebSocket signaling. Features intelligent message routing, complete network discovery, and multiple communication modes.

## 🚀 Key Features

### 🔗 Direct P2P Connections
- WebRTC-based peer-to-peer messaging (no server relay)
- Multiple simultaneous connections
- NAT traversal using STUN servers
- Real-time connection establishment

### 🛤️ Intelligent Message Routing
- **Multi-hop routing**: Send messages through multiple intermediary peers
- **Complete path discovery**: Full network topology awareness
- **Automatic route propagation**: Learn about the entire network through any connection
- **Smart message forwarding**: Messages find the optimal path to destination
- **Loop prevention**: Built-in hop count limits prevent infinite loops

### 📡 Multiple Communication Modes
- **Direct messages**: `/msg [user] [message]` - Point-to-point communication
- **Localcast**: `/localcast [message]` - Broadcast to direct connections only
- **Network broadcast**: `/broadcast [message]` - Reach entire network (direct + routed)
- **Timestamped messages**: All messages include precise timestamps

### 🔐 Connection Security
- **Request-based connections**: Users must explicitly request and accept connections
- **Pending request management**: Track incoming/outgoing connection requests
- **Connection validation**: Accept only valid connection requests

## 🌐 Network Topology Example

```
alice ←→ bob ←→ charlie ←→ steven
```

**Alice's view:**
- **Directly connected**: `[bob]`
- **Reachable via routing**: 
  - `alice -> bob -> charlie`
  - `alice -> bob -> charlie -> steven`

**Message flow**: When alice sends `/msg steven hello`, the message routes:
`alice → bob → charlie → steven`

## 🎯 Message Types & Display

### Message Labels
- `[DIRECT]` - Direct peer-to-peer message
- `[ROUTED]` - Message received via multi-hop routing
- `[LOCALCAST]` - Broadcast to direct connections
- `[BROADCAST]` - Network-wide broadcast message

### Example Message Display
```
15:04:05 [DIRECT] bob: Hello Alice!
15:04:12 [ROUTED] steven: Hi from across the network
15:04:20 [BROADCAST] charlie: Announcement to everyone
15:04:25 [LOCALCAST] alice: Message to nearby peers
```

## 🛠️ Usage Guide

### Start the Signaling Server
```bash
go run cmd/signaling-server/main.go
```

### Start Chat Clients
```bash
go run cmd/chat/main.go -server ws://localhost:8080/ws
```

### Available Commands
- `/connect [user]` - Request connection to user
- `/accept [user]` - Accept incoming connection request
- `/decline [user]` - Decline connection request
- `/msg [user] [message]` - Send direct or routed message
- `/localcast [message]` - Broadcast to direct connections only
- `/broadcast [message]` - Broadcast to entire network (direct + routed)
- `/who` - Display network topology and connections
- `/drop [user]` - Disconnect from user
- `/quit` - Exit application

### Network Testing Scenario

1. **Setup 4-node network**:
   ```bash
   # Terminal 1: alice
   go run cmd/chat/main.go
   
   # Terminal 2: bob  
   go run cmd/chat/main.go
   
   # Terminal 3: charlie
   go run cmd/chat/main.go
   
   # Terminal 4: steven
   go run cmd/chat/main.go
   ```

2. **Establish connections**:
   ```
   # Create chain: alice ←→ bob ←→ charlie ←→ steven
   alice: /connect bob
   bob: /accept alice
   bob: /connect charlie  
   charlie: /accept bob
   charlie: /connect steven
   steven: /accept charlie
   ```

3. **Test routing**:
   ```
   alice: /who
   # Shows: alice -> bob -> charlie -> steven
   
   alice: /msg steven Hello from the other end!
   # Steven receives: "15:04:05 [ROUTED] alice: Hello from the other end!"
   ```

4. **Test broadcasts**:
   ```
   alice: /broadcast Network announcement!
   # All users receive: "15:04:10 [BROADCAST] alice: Network announcement!"
   
   bob: /localcast Local update
   # Only alice and charlie receive: "15:04:15 [LOCALCAST] bob: Local update"
   ```

## 🏗️ Technical Architecture

### Core Components
- **Signaling Server** (`cmd/signaling-server/`): WebSocket-based connection coordination
- **Chat Client** (`cmd/chat/`): Main P2P client application
- **WebRTC Engine** (`internal/client/`): Peer connection and routing management
- **Protocol Layer** (`internal/proto/`): Message format definitions
- **User Interface** (`internal/ui/`): Command-line interface

### Routing Algorithm
1. **Peer List Exchange**: When peers connect, they exchange complete network topology
2. **Path Building**: Each client maintains full routing paths to all reachable users
3. **Route Propagation**: Network topology updates propagate through all connections
4. **Message Forwarding**: Messages automatically route through optimal paths
5. **Connection Management**: Routes update automatically when connections change

### Network Discovery Process
1. **Initial Connection**: `alice ←→ bob` (direct connection established)
2. **Network Expansion**: `bob ←→ charlie` (bob learns charlie, tells alice)
3. **Full Discovery**: `charlie ←→ steven` (charlie learns steven, tells bob, bob tells alice)
4. **Complete Topology**: All nodes know complete network structure

## 🌍 Cross-Network Testing

### Local Network Testing
```bash
# Start signaling server on main machine
go run cmd/signaling-server/main.go -addr 0.0.0.0:8080

# Connect clients from different devices
go run cmd/chat/main.go -server ws://192.168.1.100:8080/ws
```

### Internet Testing with ngrok
```bash
# Expose signaling server publicly
ngrok http 8080

# Connect clients using ngrok URL
go run cmd/chat/main.go -server ws://abc123.ngrok.io/ws
```

## 🔧 Dependencies

- **Go 1.22+**
- **Pion WebRTC v4** - WebRTC implementation
- **Gorilla WebSocket** - WebSocket signaling
- **Google STUN servers** - NAT traversal

## 🎯 Use Cases

- **Decentralized messaging**: No central message server required
- **Mesh networking**: Automatic network topology discovery
- **Resilient communication**: Messages route around failed connections  
- **Group coordination**: Multiple broadcast modes for different scopes
- **Development/testing**: Network protocol and P2P application testing

---

**Whisper** demonstrates advanced P2P networking concepts including WebRTC data channels, intelligent routing algorithms, and distributed network topology management - all in a clean, production-ready Go codebase.