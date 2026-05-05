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

      socket.on('connect_error', (err) => {
        p2pLog('Signaling connection failed. Check your internet/VPN.', 'warn');
        console.error('Socket.io error:', err);
      });

      socket.on('peer-joined', async () => {
        p2pLog('Peer detected! Preparing handshake...', 'ok');
        setStatus('⚡ Peer connected — establishing tunnel...');
        showPeerOnRadar('P');
        
        // Sender initiates the handshake
        if (role === 'sender') {
          // Re-create/Initialize PC only when peer actually joins to ensure fresh ICE gathering
          createPeerConnection();
          setTimeout(() => createOffer(), 500); 
        }
      });

      socket.on('peer-left', () => {
        p2pLog('Peer disconnected.', 'warn');
        setStatus('❌ Peer disconnected');
        cleanup();
      });

      socket.on('signal', async (data) => {
        try {
          // ALWAYS ensure PeerConnection exists
          if (!pc) createPeerConnection();

          if (data.type === 'offer') {
            p2pLog('📡 Receiving offer...', 'info');
            await pc.setRemoteDescription(new RTCSessionDescription(data));

            // Process queued ICE candidates AFTER remote description
            while (iceCandidateQueue.length > 0) {
              const cand = iceCandidateQueue.shift();
              if (cand) {
                await pc.addIceCandidate(cand).catch(e => console.warn('Late ICE error', e));
              }
            }

            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit('signal', pc.localDescription.toJSON ? pc.localDescription.toJSON() : pc.localDescription);
          } 
          else if (data.type === 'answer') {
            p2pLog('📡 Receiving answer...', 'info');
            await pc.setRemoteDescription(new RTCSessionDescription(data));

            while (iceCandidateQueue.length > 0) {
              const cand = iceCandidateQueue.shift();
              if (cand) {
                await pc.addIceCandidate(cand).catch(e => console.warn('Late ICE error', e));
              }
            }
          } 
          else if (data.candidate !== undefined) {
            if (data.candidate) {
              const candidate = new RTCIceCandidate(data);
              if (pc.remoteDescription && pc.remoteDescription.type) {
                await pc.addIceCandidate(candidate).catch(e => console.warn('ICE error', e));
              } else {
                iceCandidateQueue.push(candidate);
              }
            }
          }
        } catch (e) {
          console.error('Signal error:', e);
          p2pLog('Handshake error. Refresh and try again.', 'warn');
        }
      });
    });
  }

  function createPeerConnection() {
    if (pc) {
      try { pc.close(); } catch(e){}
    }
    iceCandidateQueue = [];
    pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        socket.emit('signal', e.candidate.toJSON());
      }
    };

    pc.oniceconnectionstatechange = () => {
      p2pLog(`📡 ICE State: ${pc.iceConnectionState}`, 'info');
      if (pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed') {
        showRadar(false);
        setStatus('🟢 Tunnel established — ready to transfer');
        p2pLog('WebRTC tunnel is LIVE! Encrypted and direct.', 'ok');
      } else if (pc.iceConnectionState === 'disconnected' || pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'closed') {
        setStatus('❌ Connection lost');
        p2pLog('Connection interrupted.', 'warn');
      }
    };

    pc.onconnectionstatechange = () => {
      console.log("Connection State:", pc.connectionState);
    };

    pc.ondatachannel = (e) => {
      dc = e.channel;
      setupDataChannel();
    };
  }

  function setupDataChannel() {
    if (!dc) return;
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
      setStatus('❌ Connection closed');
    };

    dc.onmessage = (e) => {
      if (typeof e.data === 'string') {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'file-meta') {
            recvMeta = msg; recvChunks = []; recvSize = 0;
            p2pLog(`Receiving: ${msg.name}`, 'ok');
            setStatus(`📥 Receiving: ${msg.name}`);
          } else if (msg.type === 'file-done') { assembleFile(); }
        } catch(e) {}
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
    if (!pc) createPeerConnection();
    p2pLog('📡 Initiating WebRTC handshake...', 'info');
    dc = pc.createDataChannel('raazvault-p2p', { ordered: true });
    setupDataChannel();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit('signal', pc.localDescription.toJSON ? pc.localDescription.toJSON() : pc.localDescription);
  }

  async function sendFile(file) {
    if (!dc || dc.readyState !== 'open') {
      p2pLog('Data channel is not open. Cannot send.', 'warn');
      return;
    }
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
      
      // Handle backpressure
      while (dc.bufferedAmount > 4 * 1024 * 1024) { // 4MB buffer limit
        await new Promise(r => setTimeout(r, 50));
      }
      
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
    role = 'sender'; 
    await connectSocket(); 
    // Don't create PC yet, wait for peer-joined
    socket.emit('create-room', (res) => {
      if (res.ok) {
        const initials = window.currentUser ? getInitials(window.currentUser.name) : '??';
        showRadar(true, initials);
        roomCode = res.code;
        $('p2pCode').textContent = res.code.split('').join('  ');
        $('p2pCodeBox').style.display = 'block';
        $('p2pJoinBox').style.display = 'none';
        $('p2pActions').style.display = 'none';
        p2pLog(`Room created: ${res.code}. Waiting for peer...`, 'info');
      }
    });
  }

  async function joinRoom(code) {
    if (!code || code.trim().length < 6) {
      p2pLog('Invalid room code.', 'warn');
      return;
    }
    const cleanCode = code.replace(/\s/g, ''); // Strip all whitespace
    role = 'receiver'; 
    await connectSocket(); 
    
    socket.emit('join-room', cleanCode, (res) => {
      if (res.ok) {
        const initials = window.currentUser ? getInitials(window.currentUser.name) : '??';
        showRadar(true, initials);
        roomCode = cleanCode;
        setStatus('⚡ Connecting to peer...');
        $('p2pActions').style.display = 'none';
        $('p2pJoinBox').style.display = 'none';
        p2pLog(`Joined room ${cleanCode}. Awaiting offer...`, 'info');
      } else {
        p2pLog(`Error: ${res.error || 'Could not join room.'}`, 'warn');
        setStatus('❌ ' + (res.error || 'Join failed'));
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
