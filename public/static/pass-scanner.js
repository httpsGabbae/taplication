(() => {
  const startButton = document.getElementById('start-scan');
  if (!startButton) return;
  const stopButton = document.getElementById('stop-scan');
  const frame = document.getElementById('camera-frame');
  const video = document.getElementById('qr-video');
  const message = document.getElementById('scan-message');
  const fileInput = document.getElementById('qr-file');
  let stream = null;
  let detector = null;
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d', { willReadFrequently: true });
  let running = false;
  let busy = false;

  function setMessage(value) { message.textContent = value; }
  function stop() {
    running = false;
    if (stream) stream.getTracks().forEach(track => track.stop());
    stream = null;
    video.srcObject = null;
    frame.hidden = true;
    stopButton.hidden = true;
    startButton.hidden = false;
  }
  async function getDetector() {
    if ('BarcodeDetector' in window && !detector) {
      try { detector = new BarcodeDetector({ formats: ['qr_code'] }); } catch (_) { detector = null; }
    }
    if (!detector && typeof window.jsQR !== 'function') throw new Error('QR reading is unavailable in this browser. Use your phone camera or enter your details.');
    return detector;
  }
  function openPass(rawValue) {
    let url;
    try { url = new URL(rawValue, location.href); } catch (_) { return false; }
    if (url.origin !== location.origin || !/^\/tap\/[A-Za-z0-9-]+$/.test(url.pathname) || !url.searchParams.get('token')) {
      setMessage('That QR is not a TapLication pass. Scan the QR printed on the pass.');
      return false;
    }
    stop();
    setMessage('Pass found. Opening it now…');
    location.assign(url.pathname + url.search);
    return true;
  }
  async function inspect(source) {
    const nativeDetector = await getDetector();
    let value;
    if (nativeDetector) {
      try {
        const codes = await nativeDetector.detect(source);
        value = codes[0]?.rawValue;
      } catch (_) { /* Use the bundled decoder below. */ }
    }
    if (!value && typeof window.jsQR === 'function') {
      const sourceWidth = source.videoWidth || source.width;
      const sourceHeight = source.videoHeight || source.height;
      const limit = source.tagName === 'VIDEO' ? 960 : 1600;
      const scale = Math.min(1, limit / Math.max(sourceWidth, sourceHeight));
      canvas.width = Math.round(sourceWidth * scale);
      canvas.height = Math.round(sourceHeight * scale);
      context.drawImage(source, 0, 0, canvas.width, canvas.height);
      const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
      value = window.jsQR(pixels.data, pixels.width, pixels.height)?.data;
    }
    if (!value) return false;
    openPass(value);
    return true;
  }
  async function scanFrame() {
    if (!running) return;
    if (!busy && video.readyState >= 2) {
      busy = true;
      try { await inspect(video); } catch (_) { setMessage('Could not read the QR. Try better light or enter your details.'); }
      busy = false;
    }
    if (running) window.setTimeout(scanFrame, 160);
  }
  startButton.addEventListener('click', async () => {
    try {
      await getDetector();
      if (!navigator.mediaDevices?.getUserMedia) throw new Error('Camera access needs HTTPS and a supported browser. Use your phone camera or enter your details.');
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
      video.srcObject = stream;
      await video.play();
      running = true;
      frame.hidden = false;
      startButton.hidden = true;
      stopButton.hidden = false;
      setMessage('Hold the printed QR inside the frame.');
      scanFrame();
    } catch (error) {
      stop();
      setMessage(error.name === 'NotAllowedError' ? 'Camera permission was denied. Allow it in your browser or enter your details.' : (error.message || 'Camera unavailable. Enter your details instead.'));
    }
  });
  stopButton.addEventListener('click', () => { stop(); setMessage('Camera stopped.'); });
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    try {
      const bitmap = window.createImageBitmap ? await createImageBitmap(file) : await new Promise((resolve, reject) => {
        const image = new Image();
        const objectUrl = URL.createObjectURL(file);
        image.onload = () => { URL.revokeObjectURL(objectUrl); resolve(image); };
        image.onerror = () => { URL.revokeObjectURL(objectUrl); reject(new Error('Could not open that image.')); };
        image.src = objectUrl;
      });
      try {
        const opened = await inspect(bitmap);
        if (!opened) setMessage('No TapLication QR found in that image. Try a clearer photo.');
      } finally { if (bitmap.close) bitmap.close(); }
    } catch (error) { setMessage(error.message || 'Could not read that image. Enter your details instead.'); }
    fileInput.value = '';
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); });
  window.addEventListener('pagehide', stop);
})();
