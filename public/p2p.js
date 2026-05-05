// ═══════════════════════════════════════════════════════════════════════════════
//  RaazVault P2P v1.6 — WebRTC Encrypted File Transfer
// ═══════════════════════════════════════════════════════════════════════════════

const P2P = (() => {
  const CHUNK_SIZE = 64 * 1024; // 64KB chunks
  const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
    { urls: 'stun:stun3.l.google.com:19302' },
    { urls: 'stun:stun4.l.google.com:19302' },
    {
      urls: "turn:openrelay.metered.ca:80",
      username: "openrelayproject",
      credential: "openrelayproject"
    },
    {
      urls: "turn:openrelay.metered.ca:443",
      username: "openrelayproject",
      credential: "openrelayproject"
    },
    {
      urls: "turn:openrelay.metered.ca:443?transport=tcp",
      username: "openrelayproject",
      credential: "openrelayproject"
    }
  ];

  let socket = null;
  let pc = null;
  let dc = null;
  let role = null;
  let roomCode = null;
  let iceCandidateQueue = [];

  let recvMeta = null;
  let recvChunks = [];
  let recvSize = 0;

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
  }

  function showRadar(show, userInitials = '??') {
    const r = $('p2pRadar'), rt = $('p2pRadarText');
    const uDot = $('radarUserDot'), pDot = $('radarPeerDot');
    if (r && rt) {
      if (show) { 
        r.classList.add('active'); 
        rt.classList.add('active'); 
        if (uDot) { uDot.style.display = 'flex'; uDot.textContent = userInitials; }
      }
      else { 
        r.classList.remove('active'); rt.classList.remove('active'); 
        if (uDot) uDot.style.display = 'none';
        if (pDot) pDot.style.display = 'none';
      }
    }
  }

  function showPeerOnRadar(peerInitials = 'P') {
    const pDot = $('radarPeerDot');
    if (pDot) {
      pDot.style.display = 'flex';
      pDot.textContent = peerInitials;
      const angle = Math.random() * Math.PI * 2;
      const radius = 100;
      pDot.style.left = `calc(50% + ${Math.cos(angle) * radius}px)`;
      pDot.style.top = `calc(50% + ${Math.sin(angle) * radius}px)`;
      pDot.style.transform = 'translate(-50%, -50%)';
    }
  }

  async function connectSocket() {
    if (socket && socket.connected) return;
    return new Promise((resolve) => {
      socket = io();
      socket.on('connect', () => {
        p2pLog('RaazVault P2P v1.6 - Ready', 'info');
        p2pLog('Connected to signaling server', 'ok');
        resolve();
      });

      socket.on('peer-joined', async () => {
        p2pLog('Peer detected! Preparing handshake...', 'ok');
        setStatus('⚡ Peer connected — establishing tunnel...');
        showPeerOnRadar('P');
        // Small delay to prevent race conditions during signaling
        setTimeout(() => {
          if (role === 'sender') createOffer();
        }, 1000);
      });

      socket.on('peer-left', () => {
        p2pLog('Peer disconnected.', 'warn');
        setStatus('❌ Peer disconnected');
        cleanup();
      });

      socket.on('signal', async (data) => {
        try {
          if (data.type === 'offer') {
            p2pLog('📡 Receiving offer...', 'info');
            await pc.setRemoteDescription(new RTCSessionDescription(data));
            while (iceCandidateQueue.length > 0) {
              await pc.addIceCandidate(iceCandidateQueue.shift());
            }
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit('signal', pc.localDescription);
          } else if (data.type === 'answer') {
            p2pLog('📡 Receiving answer...', 'info');
            await pc.setRemoteDescription(new RTCSessionDescription(data));
            while (iceCandidateQueue.length > 0) {
              await pc.addIceCandidate(iceCandidateQueue.shift());
            }
          } else if (data.candidate) {
            const candidate = new RTCIceCandidate(data);
            if (pc.remoteDescription && pc.remoteDescription.type) {
              await pc.addIceCandidate(candidate);
            } else {
              iceCandidateQueue.push(candidate);
            }
          }
        } catch (e) {
          console.error('Signal error', e);
        }
      });
    });
  }

  function createPeerConnection() {
    iceCandidateQueue = [];
    pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    pc.onicecandidate = (e) => {
      if (e.candidate) socket.emit('signal', e.candidate);
    };

    pc.oniceconnectionstatechange = () => {
      p2pLog(`📡 ICE State: ${pc.iceConnectionState}`, 'info');
      if (pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed') {
        showRadar(false);
        setStatus('🟢 Tunnel established — ready to transfer');
        p2pLog('WebRTC tunnel is LIVE! Encrypted and direct.', 'ok');
      } else if (pc.iceConnectionState === 'disconnected' || pc.iceConnectionState === 'failed') {
        showRadar(false);
        setStatus('❌ Connection lost');
      }
    };

    pc.ondatachannel = (e) => {
      dc = e.channel;
      setupDataChannel();
    };
  }

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

    dc.onmessage = (e) => {
      if (typeof e.data === 'string') {
        const msg = JSON.parse(e.data);
        if (msg.type === 'file-meta') {
          recvMeta = msg; recvChunks = []; recvSize = 0;
          p2pLog(`Receiving: ${msg.name}`, 'ok');
          setStatus(`📥 Receiving: ${msg.name}`);
        } else if (msg.type === 'file-done') { assembleFile(); }
      } else {
        recvChunks.push(e.data);
        recvSize += e.data.byteLength;
        if (recvMeta) {
          const pct = Math.round((recvSize / recvMeta.size) * 100);
          setProgress(pct);
        }
      }
    };
  }

  async function createOffer() {
    p2pLog('📡 Initiating WebRTC handshake...', 'info');
    createPeerConnection();
    dc = pc.createDataChannel('raazvault-p2p', { ordered: true });
    setupDataChannel();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit('signal', pc.localDescription);
  }

  async function sendFile(file) {
    if (!dc || dc.readyState !== 'open') return;
    p2pLog(`Sending: ${file.name}`, 'ok');
    setStatus(`📤 Sending: ${file.name}`);
    dc.send(JSON.stringify({ type: 'file-meta', name: file.name, size: file.size, mime: file.type || 'application/octet-stream' }));
    const buffer = await file.arrayBuffer();
    const totalChunks = Math.ceil(buffer.byteLength / CHUNK_SIZE);
    let sent = 0;
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, buffer.byteLength);
      const chunk = buffer.slice(start, end);
      while (dc.bufferedAmount > 16 * CHUNK_SIZE) { await new Promise(r => setTimeout(r, 20)); }
      dc.send(chunk);
      sent += chunk.byteLength;
      setProgress(Math.round((sent / buffer.byteLength) * 100));
    }
    dc.send(JSON.stringify({ type: 'file-done' }));
    p2pLog('File sent successfully!', 'ok');
    setStatus('✅ File sent!');
  }

  function assembleFile() {
    if (!recvMeta) return;
    const blob = new Blob(recvChunks, { type: recvMeta.mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = recvMeta.name; a.click();
    p2pLog(`Downloaded: ${recvMeta.name}`, 'ok');
    setStatus('✅ File received!');
    recvMeta = null; recvChunks = []; recvSize = 0;
  }

  async function createRoom() {
    role = 'sender'; await connectSocket(); createPeerConnection();
    socket.emit('create-room', (res) => {
      if (res.ok) {
        const initials = window.currentUser ? getInitials(window.currentUser.name) : '??';
        showRadar(true, initials);
        roomCode = res.code;
        $('p2pCode').textContent = res.code.split('').join('  ');
        $('p2pCodeBox').style.display = 'block';
        $('p2pJoinBox').style.display = 'none';
        $('p2pActions').style.display = 'none';
      }
    });
  }

  async function joinRoom(code) {
    role = 'receiver'; await connectSocket(); createPeerConnection();
    socket.emit('join-room', code.trim(), (res) => {
      if (res.ok) {
        const initials = window.currentUser ? getInitials(window.currentUser.name) : '??';
        showRadar(true, initials);
        roomCode = code.trim();
        setStatus('⚡ Connecting to peer...');
        $('p2pActions').style.display = 'none';
        $('p2pJoinBox').style.display = 'none';
      }
    });
  }

  function cleanup() {
    showRadar(false);
    if (dc) { try { dc.close(); } catch(e){} dc = null; }
    if (pc) { try { pc.close(); } catch(e){} pc = null; }
  }

  function getInitials(name) {
    if (!name) return '??';
    const names = name.trim().split(/\s+/);
    if (names.length > 1) return (names[0][0] + names[names.length - 1][0]).toUpperCase();
    return names[0].substring(0, 2).toUpperCase();
  }

  return { createRoom, joinRoom, sendFile };
})();
