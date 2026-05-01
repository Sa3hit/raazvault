// ═══════════════════════════════════════════════════════════════════════════════
//  RaazVault P2P — WebRTC Encrypted File Transfer
// ═══════════════════════════════════════════════════════════════════════════════

const P2P = (() => {
  const CHUNK_SIZE = 64 * 1024; // 64KB chunks
  const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' }
  ];

  let socket = null;
  let pc = null; // RTCPeerConnection
  let dc = null; // RTCDataChannel
  let role = null; // 'sender' or 'receiver'
  let roomCode = null;

  // Receive state
  let recvMeta = null;
  let recvChunks = [];
  let recvSize = 0;

  // UI references
  const $ = id => document.getElementById(id);

  function p2pLog(msg, cls = '') {
    const el = $('p2pLog');
    if (el) el.innerHTML += `<br><span class="${cls}">[${new Date().toLocaleTimeString('en-GB')}] ${msg}</span>`;
  }

  function setStatus(text) {
    const el = $('p2pStatus');
    if (el) el.textContent = text;
  }

  function setProgress(pct, speed) {
    const bar = $('p2pBar');
    if (bar) bar.style.width = pct + '%';
    const info = $('p2pProgress');
    if (info) info.textContent = speed ? `${pct}% · ${speed}` : `${pct}%`;
  }

  // ─── SOCKET CONNECTION ─────────────────────────────────────────────────
  function connectSocket() {
    if (socket && socket.connected) return Promise.resolve();
    return new Promise((resolve) => {
      socket = io();
      socket.on('connect', () => {
        p2pLog('Connected to signaling server', 'ok');
        resolve();
      });

      socket.on('peer-joined', () => {
        p2pLog('Peer connected! Setting up encrypted tunnel...', 'ok');
        setStatus('⚡ Peer connected — establishing tunnel...');
        createOffer();
      });

      socket.on('peer-left', () => {
        p2pLog('Peer disconnected.', 'warn');
        setStatus('❌ Peer disconnected');
        cleanup();
      });

      socket.on('signal', async (data) => {
        try {
          if (data.type === 'offer') {
            await pc.setRemoteDescription(new RTCSessionDescription(data));
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit('signal', pc.localDescription);
          } else if (data.type === 'answer') {
            await pc.setRemoteDescription(new RTCSessionDescription(data));
          } else if (data.candidate) {
            await pc.addIceCandidate(new RTCIceCandidate(data));
          }
        } catch (e) {
          p2pLog('Signal error: ' + e.message, 'warn');
        }
      });
    });
  }

  // ─── CREATE WEBRTC PEER CONNECTION ─────────────────────────────────────
  function createPeerConnection() {
    pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    pc.onicecandidate = (e) => {
      if (e.candidate) socket.emit('signal', e.candidate);
    };

    pc.oniceconnectionstatechange = () => {
      const state = pc.iceConnectionState;
      if (state === 'connected' || state === 'completed') {
        setStatus('🟢 Tunnel established — ready to transfer');
        p2pLog('WebRTC tunnel is LIVE! Encrypted and direct.', 'ok');
      } else if (state === 'disconnected' || state === 'failed') {
        p2pLog('Connection lost.', 'warn');
        setStatus('❌ Connection lost');
      }
    };

    // Receiver: listen for incoming data channel
    pc.ondatachannel = (e) => {
      dc = e.channel;
      setupDataChannel();
    };
  }

  // ─── DATA CHANNEL SETUP ────────────────────────────────────────────────
  function setupDataChannel() {
    dc.binaryType = 'arraybuffer';

    dc.onopen = () => {
      p2pLog('Data channel open — encrypted P2P tunnel ready!', 'ok');
      if (role === 'sender') {
        setStatus('🟢 Ready — select a file to send');
        $('p2pFileSection').style.display = 'block';
      } else {
        setStatus('🟢 Connected — waiting for file...');
      }
    };

    dc.onclose = () => {
      p2pLog('Data channel closed.', 'warn');
    };

    dc.onmessage = (e) => {
      // Receiver handles incoming data
      if (typeof e.data === 'string') {
        const msg = JSON.parse(e.data);
        if (msg.type === 'file-meta') {
          recvMeta = msg;
          recvChunks = [];
          recvSize = 0;
          p2pLog(`Receiving: ${msg.name} (${formatSize(msg.size)})`, 'ok');
          setStatus(`📥 Receiving: ${msg.name}`);
          setProgress(0, '');
        } else if (msg.type === 'file-done') {
          assembleFile();
        }
      } else {
        // Binary chunk
        recvChunks.push(e.data);
        recvSize += e.data.byteLength;
        if (recvMeta) {
          const pct = Math.round((recvSize / recvMeta.size) * 100);
          setProgress(pct, formatSize(recvSize) + ' / ' + formatSize(recvMeta.size));
        }
      }
    };
  }

  // ─── SENDER: CREATE OFFER ──────────────────────────────────────────────
  async function createOffer() {
    createPeerConnection();
    dc = pc.createDataChannel('raazvault-p2p', { ordered: true });
    setupDataChannel();

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit('signal', pc.localDescription);
  }

  // ─── SENDER: SEND FILE ─────────────────────────────────────────────────
  async function sendFile(file) {
    if (!dc || dc.readyState !== 'open') {
      p2pLog('Channel not ready. Wait for peer.', 'warn');
      return;
    }

    p2pLog(`Sending: ${file.name} (${formatSize(file.size)})`, 'ok');
    setStatus(`📤 Sending: ${file.name}`);

    // Send metadata first
    dc.send(JSON.stringify({
      type: 'file-meta',
      name: file.name,
      size: file.size,
      mime: file.type || 'application/octet-stream'
    }));

    // Read and send chunks
    const buffer = await file.arrayBuffer();
    const totalChunks = Math.ceil(buffer.byteLength / CHUNK_SIZE);
    let sent = 0;
    const startTime = Date.now();

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, buffer.byteLength);
      const chunk = buffer.slice(start, end);

      // Backpressure: wait if buffer is full
      while (dc.bufferedAmount > 16 * CHUNK_SIZE) {
        await new Promise(r => setTimeout(r, 20));
      }

      dc.send(chunk);
      sent += chunk.byteLength;

      const pct = Math.round((sent / buffer.byteLength) * 100);
      const elapsed = (Date.now() - startTime) / 1000;
      const speed = elapsed > 0 ? formatSize(sent / elapsed) + '/s' : '';
      setProgress(pct, speed);
    }

    dc.send(JSON.stringify({ type: 'file-done' }));
    p2pLog('File sent successfully!', 'ok');
    setStatus('✅ File sent!');
  }

  // ─── RECEIVER: ASSEMBLE FILE ───────────────────────────────────────────
  function assembleFile() {
    if (!recvMeta) return;

    const blob = new Blob(recvChunks, { type: recvMeta.mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = recvMeta.name;
    a.click();
    URL.revokeObjectURL(url);

    p2pLog(`Downloaded: ${recvMeta.name} (${formatSize(recvMeta.size)})`, 'ok');
    setStatus('✅ File received and downloaded!');
    setProgress(100, 'Complete');

    recvMeta = null;
    recvChunks = [];
    recvSize = 0;
  }

  // ─── CREATE ROOM (SENDER) ─────────────────────────────────────────────
  async function createRoom() {
    role = 'sender';
    await connectSocket();
    createPeerConnection();

    socket.emit('create-room', (res) => {
      if (res.ok) {
        roomCode = res.code;
        p2pLog(`Room created: ${res.code}`, 'ok');
        setStatus('⏳ Waiting for peer to join...');
        $('p2pCode').textContent = res.code.split('').join('  ');
        $('p2pCodeBox').style.display = 'block';
        $('p2pJoinBox').style.display = 'none';
        $('p2pActions').style.display = 'none';
      } else {
        p2pLog('Failed to create room', 'warn');
      }
    });
  }

  // ─── JOIN ROOM (RECEIVER) ──────────────────────────────────────────────
  async function joinRoom(code) {
    role = 'receiver';
    await connectSocket();
    createPeerConnection();

    socket.emit('join-room', code.trim(), (res) => {
      if (res.ok) {
        roomCode = code.trim();
        p2pLog(`Joined room: ${code}`, 'ok');
        setStatus('⚡ Connecting to peer...');
        $('p2pActions').style.display = 'none';
        $('p2pJoinBox').style.display = 'none';
      } else {
        p2pLog(res.error, 'warn');
        setStatus('❌ ' + res.error);
      }
    });
  }

  // ─── CLEANUP ───────────────────────────────────────────────────────────
  function cleanup() {
    if (dc) { try { dc.close(); } catch(e){} dc = null; }
    if (pc) { try { pc.close(); } catch(e){} pc = null; }
    $('p2pFileSection').style.display = 'none';
  }

  // ─── HELPERS ───────────────────────────────────────────────────────────
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
  }

  // ─── PUBLIC API ────────────────────────────────────────────────────────
  return { createRoom, joinRoom, sendFile };
})();
