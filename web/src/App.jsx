import { useMemo, useState, useEffect, useRef } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:3001";
const ACCURACY_THRESHOLD = 50; // meters
const DB_NAME = "LocationProofDB";
const DB_VERSION = 1;
const STORE_NAME = "keys";

// IndexedDB helpers
async function openDB() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function getKeyFromDB() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).get("deviceKey");
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function saveKeyToDB(keyData) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const req = tx.objectStore(STORE_NAME).put(keyData, "deviceKey");
    req.onsuccess = () => res();
    req.onerror = () => rej(req.error);
  });
}

// Crypto utilities for device signing
async function generateKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
}

async function signPayload(privateKey, payload) {
  const encoder = new TextEncoder();
  const signature = await window.crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    encoder.encode(payload)
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function exportPublicKey(publicKey) {
  const exported = await window.crypto.subtle.exportKey("spki", publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

async function importPublicKey(publicKeyB64) {
  const binaryString = atob(publicKeyB64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  return await window.crypto.subtle.importKey("spki", bytes, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
}

// Hash file for integrity
async function hashFile(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const bytes = new Uint8Array(hashBuffer);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default function App() {
  const [tab, setTab] = useState("workflow");
  const [status, setStatus] = useState("");
  const [pos, setPos] = useState(null);
  const [photoUrl, setPhotoUrl] = useState(null);
  const [photoFile, setPhotoFile] = useState(null);
  const [photoSha, setPhotoSha] = useState(null);
  const [vendorName, setVendorName] = useState("");
  const [loading, setLoading] = useState(false);
  const [visitId, setVisitId] = useState(null);
  const [checkInAt, setCheckInAt] = useState(null);
  const [checkOutAt, setCheckOutAt] = useState(null);
  const [keyPair, setKeyPair] = useState(null);
  const [publicKeyB64, setPublicKeyB64] = useState(null);
  const [visits, setVisits] = useState([]);
  const [loadingVisits, setLoadingVisits] = useState(false);
  const [cameraActive, setCameraActive] = useState(false);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [mode, setMode] = useState("variant");
  const [modal, setModal] = useState({
    open: false,
    title: "",
    message: "",
    confirmLabel: "OK",
    cancelLabel: null
  });
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const confirmResolverRef = useRef(null);

  // Initialize device keys from IndexedDB on mount
  useEffect(() => {
    (async () => {
      try {
        const stored = await getKeyFromDB();
        if (stored) {
          setStatus("✓ Device key loaded from storage");
          setKeyPair(stored.keyPair);
          setPublicKeyB64(stored.publicKeyB64);
        } else {
          setStatus("Generating new device key...");
          const pair = await generateKeyPair();
          const pubKey = await exportPublicKey(pair.publicKey);
          setKeyPair(pair);
          setPublicKeyB64(pubKey);
          await saveKeyToDB({ keyPair: pair, publicKeyB64: pubKey });
          setStatus("✓ Device key generated and stored");
        }
      } catch (e) {
        setStatus("Failed to initialize cryptography: " + e.message);
      }
    })();
  }, []);

  // Load recent visits
  const loadVisits = async () => {
    setLoadingVisits(true);
    try {
      const res = await fetch(`${API_BASE}/api/visits/recent?limit=20`);
      if (res.ok) {
        const data = await res.json();
        setVisits(data.items || []);
      }
    } catch (e) {
      console.error("Error loading visits:", e);
    }
    setLoadingVisits(false);
  };

  useEffect(() => {
    loadVisits();
  }, []);

  useEffect(() => {
    if (tab === "history") {
      loadVisits();
    }
  }, [tab]);

  const normalizedVendorName = vendorName.trim().toLowerCase();
  const duplicateVisit = useMemo(() => {
    if (!normalizedVendorName) return null;
    return visits.find((v) => {
      const current = String(v.vendorName || "").trim().toLowerCase();
      return current === normalizedVendorName;
    });
  }, [normalizedVendorName, visits]);

  const openModal = ({ title, message, confirmLabel = "OK", cancelLabel = null }) => {
    return new Promise((resolve) => {
      confirmResolverRef.current = resolve;
      setModal({ open: true, title, message, confirmLabel, cancelLabel });
    });
  };

  const closeModal = (result) => {
    setModal((prev) => ({ ...prev, open: false }));
    const resolver = confirmResolverRef.current;
    confirmResolverRef.current = null;
    if (resolver) resolver(result);
  };

  const alertUser = (title, message) => openModal({ title, message, confirmLabel: "OK" });
  const confirmUser = (title, message) =>
    openModal({ title, message, confirmLabel: "Confirm", cancelLabel: "Cancel" });

  const canSubmit =
    !!vendorName.trim() && !!pos && !!photoUrl && !duplicateVisit && !loading;

  const getLocation = async () => {
    setStatus("Requesting location...");
    if (!navigator.geolocation) {
      setStatus("❌ Geolocation not supported");
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (p) => {
        const { latitude, longitude, accuracy } = p.coords;
        if (accuracy > ACCURACY_THRESHOLD) {
          setStatus(`⚠️ Accuracy ${Math.round(accuracy)}m exceeds threshold (${ACCURACY_THRESHOLD}m)`);
          return;
        }
        setPos({ lat: latitude, lng: longitude, accuracy });
        setStatus(`✓ Location captured (±${Math.round(accuracy)}m)`);
      },
      (err) => setStatus(`❌ ${err.message}`),
      { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
    );
  };

  const capturePhoto = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/*";
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      await processPhoto(file);
    };
    input.click();
  };

  const startCamera = async () => {
    try {
      setCameraActive(true);
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        setStatus("📷 Camera ready - tap photo button to capture");
      }
    } catch (e) {
      setStatus("❌ Camera access denied: " + e.message);
      setCameraActive(false);
    }
  };

  const captureFromCamera = async () => {
    if (!videoRef.current || !canvasRef.current) return;
    try {
      const ctx = canvasRef.current.getContext("2d");
      canvasRef.current.width = videoRef.current.videoWidth;
      canvasRef.current.height = videoRef.current.videoHeight;
      ctx.drawImage(videoRef.current, 0, 0);
      
      canvasRef.current.toBlob(async (blob) => {
        const file = new File([blob], "camera-capture.jpg", { type: "image/jpeg" });
        await processPhoto(file);
        
        // Stop camera
        if (videoRef.current?.srcObject) {
          videoRef.current.srcObject.getTracks().forEach(t => t.stop());
        }
        setCameraActive(false);
      }, "image/jpeg", 0.9);
    } catch (e) {
      setStatus("❌ Photo capture failed: " + e.message);
    }
  };

  const processPhoto = async (file) => {
    try {
      const sha = await hashFile(file);
      
      const reader = new FileReader();
      reader.onload = (e) => setPreviewUrl(e.target.result);
      reader.readAsDataURL(file);
      
      const fd = new FormData();
      fd.append("photo", file);
      setStatus("📸 Uploading photo...");
      const res = await fetch(`${API_BASE}/api/photos`, { method: "POST", body: fd });
      if (!res.ok) throw new Error("Upload failed");
      const data = await res.json();
      setPhotoUrl(data.photoUrl);
      setPhotoSha(sha);
      setStatus("✓ Photo captured and uploaded");
    } catch (e) {
      setStatus(`❌ Photo error: ${e.message}`);
    }
  };

  const checkIn = async () => {
    if (!vendorName || vendorName.trim().length === 0) { setStatus("❌ Enter vendor name"); return; }
    if (!pos) { setStatus("❌ Set location first"); return; }
    if (!photoUrl) { setStatus("❌ Capture photo first"); return; }
    if (!keyPair) { setStatus("❌ Keys not ready"); return; }

    if (duplicateVisit) {
      setStatus("❌ Vendor name already exists");
      await alertUser(
        "Duplicate vendor",
        `Vendor "${vendorName}" already exists. Please use a unique vendor name.`
      );
      return;
    }

    const ok = await confirmUser("Confirm check-in", `Confirm check-in for vendor: ${vendorName}`);
    if (!ok) {
      setStatus("Check-in cancelled");
      return;
    }

    setLoading(true);
    try {
      setStatus("⏳ Requesting challenge...");
      const challengeRes = await fetch(`${API_BASE}/api/challenge`);
      const challenge = await challengeRes.json();

      const capturedAt = new Date().toISOString();
      const payload = [
        challenge.nonce,
        "CHECK_IN",
        vendorName,
        String(pos.lat),
        String(pos.lng),
        String(pos.accuracy),
        capturedAt,
        photoSha
      ].join("|");

      setStatus("🔐 Signing...");
      const signature = await signPayload(keyPair.privateKey, payload);

      setStatus("📤 Checking in...");
      const checkInRes = await fetch(`${API_BASE}/api/visits/check-in`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          eventType: "CHECK_IN",
          vendorName: vendorName.trim(),
          latitude: pos.lat,
          longitude: pos.lng,
          accuracyMeters: pos.accuracy,
          capturedAt,
          photoUrl,
          photoSha256: photoSha,
          devicePublicKey: publicKeyB64,
          deviceSignature: signature,
          challengeId: challenge.challengeId,
          challengeNonce: challenge.nonce
        })
      });

      if (!checkInRes.ok) {
        const txt = await checkInRes.text();
        throw new Error(txt || "Check-in failed");
      }
      const data = await checkInRes.json();
      setVisitId(data.visitId);
      setCheckInAt(capturedAt);
      setStatus("✓ Checked in successfully!");
      loadVisits();
      setPhotoUrl(null);
      setPhotoSha(null);
      setPos(null);
    } catch (e) {
      setStatus(`❌ Check-in failed: ${e.message}`);
    }
    setLoading(false);
  };

  const checkOut = async () => {
    if (!visitId) { setStatus("❌ Not checked in"); return; }
    if (!vendorName || vendorName.trim().length === 0) { setStatus("❌ Enter vendor name"); return; }
    if (!pos) { setStatus("❌ Set location first"); return; }
    if (!photoUrl) { setStatus("❌ Capture photo first"); return; }

    const ok = await confirmUser("Confirm check-out", `Confirm check-out for vendor: ${vendorName}`);
    if (!ok) {
      setStatus("Check-out cancelled");
      return;
    }

    setLoading(true);
    try {
      setStatus("⏳ Requesting challenge...");
      const challengeRes = await fetch(`${API_BASE}/api/challenge`);
      const challenge = await challengeRes.json();

      const capturedAt = new Date().toISOString();
      const payload = [
        challenge.nonce,
        "CHECK_OUT",
        vendorName,
        String(pos.lat),
        String(pos.lng),
        String(pos.accuracy),
        capturedAt,
        photoSha
      ].join("|");

      setStatus("🔐 Signing...");
      const signature = await signPayload(keyPair.privateKey, payload);

      setStatus("📤 Checking out...");
      const checkOutRes = await fetch(`${API_BASE}/api/visits/${visitId}/check-out`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          eventType: "CHECK_OUT",
          vendorName: vendorName.trim(),
          latitude: pos.lat,
          longitude: pos.lng,
          accuracyMeters: pos.accuracy,
          capturedAt,
          photoUrl,
          photoSha256: photoSha,
          devicePublicKey: publicKeyB64,
          deviceSignature: signature,
          challengeId: challenge.challengeId,
          challengeNonce: challenge.nonce
        })
      });

      if (!checkOutRes.ok) {
        const txt = await checkOutRes.text();
        throw new Error(txt || "Check-out failed");
      }
      setCheckOutAt(capturedAt);
      const duration = checkInAt ? `${Math.round((new Date() - new Date(checkInAt)) / 60000)} min` : "?";
      setStatus(`✓ Checked out! Duration: ${duration}`);
      loadVisits();
      setVisitId(null);
      setCheckInAt(null);
      setPhotoUrl(null);
      setPhotoSha(null);
      setPos(null);
    } catch (e) {
      setStatus(`❌ Check-out failed: ${e.message}`);
    }
    setLoading(false);
  };

  const exportData = (format) => {
    const url = `${API_BASE}/api/export.${format}`;
    const filename = `location_proof_${new Date().toISOString().split("T")[0]}.${format}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
  };

  const exportPublicKeyPEM = () => {
    if (!publicKeyB64) return;
    const blob = new Blob([
      "-----BEGIN PUBLIC KEY-----\n",
      publicKeyB64.match(/.{1,64}/g).join("\n"),
      "\n-----END PUBLIC KEY-----"
    ], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "device-public-key.pem";
    a.click();
  };

  return (
    <div className="app-container">
      <h1 className="app-title">📍 Location Proof - Check-In/Out</h1>

      <div className="tab-row">
        <button
          onClick={() => setTab("workflow")}
          className={`tab-button ${tab === "workflow" ? "active" : ""}`}
        >
          Workflow
        </button>
        <button
          onClick={() => setTab("history")}
          className={`tab-button ${tab === "history" ? "active" : ""}`}
        >
          History
        </button>
        <button
          onClick={() => setTab("export")}
          className={`tab-button ${tab === "export" ? "active" : ""}`}
        >
          Export
        </button>
      </div>

      {tab === "workflow" && (
        <div className="section-card">
          <p className="status-line">
            Status: {status || "Ready"} | Device Key: {publicKeyB64 ? "✓ Persistent" : "⏳"}
          </p>
          <div className="mode-toggle">
            <label className="mode-option">
              <input
                type="radio"
                name="mode"
                value="variant"
                checked={mode === "variant"}
                onChange={() => setMode("variant")}
              />
              <span>Variant</span>
            </label>
            <label className="mode-option">
              <input
                type="radio"
                name="mode"
                value="control"
                checked={mode === "control"}
                onChange={() => setMode("control")}
              />
              <span>Control</span>
            </label>
          </div>
          <div className="field-row">
            <input
              value={vendorName}
              onChange={(e) => setVendorName(e.target.value)}
              placeholder="Vendor name (required)"
              className="text-input"
            />
          </div>

          <div className="step-grid">
            <div className="panel">
              <h3>Step 1: Capture Location</h3>
              <button onClick={getLocation} className="button block">
                📍 Get GPS Location
              </button>
              {pos && (
                <div className="meta">
                  <div>Lat: {pos.lat.toFixed(6)}</div>
                  <div>Lon: {pos.lng.toFixed(6)}</div>
                  <div>Accuracy: ±{Math.round(pos.accuracy)}m</div>
                </div>
              )}
            </div>

            <div className="panel">
              <h3>Step 2: Capture Photo</h3>
              <div className="button-row">
                <button onClick={capturePhoto} className="button flex-1">
                  📁 Choose Photo
                </button>
                <button onClick={startCamera} disabled={cameraActive} className="button flex-1">
                  📷 Open Camera
                </button>
              </div>
              {photoUrl && <div className="success-text">✓ Photo uploaded</div>}
              {previewUrl && (
                <div className="preview">
                  <img src={previewUrl} alt="preview" className="preview-img" />
                </div>
              )}
            </div>
          </div>

          {cameraActive && (
            <div className="camera-panel">
              <video ref={videoRef} autoPlay playsInline className="camera-video" />
              <button onClick={captureFromCamera} className="button warn block">
                📸 Capture Photo
              </button>
            </div>
          )}

          <canvas ref={canvasRef} className="hidden" />

          {mode === "control" ? (
            <button
              onClick={checkIn}
              disabled={!canSubmit}
              className={`button primary block large ${loading ? "is-loading" : ""}`}
            >
              ✓ SUBMIT
            </button>
          ) : !visitId ? (
            <button
              onClick={checkIn}
              disabled={!pos || !photoUrl || loading}
              className={`button primary block large ${loading ? "is-loading" : ""}`}
            >
              ✓ CHECK IN
            </button>
          ) : (
            <div className="checkin-info">
              <p>✓ Checked in at {checkInAt ? new Date(checkInAt).toLocaleTimeString() : "-"}</p>
              <button
                onClick={checkOut}
                disabled={!pos || !photoUrl || loading}
                className={`button danger block large ${loading ? "is-loading" : ""}`}
              >
                ✓ CHECK OUT
              </button>
            </div>
          )}
        </div>
      )}

      {tab === "history" && (
        <div className="section-card">
          <h2>Recent Visits</h2>
          {loadingVisits ? (
            <p>Loading...</p>
          ) : visits.length === 0 ? (
            <p className="muted">No visits yet</p>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Visit ID</th>
                    <th>Vendor</th>
                    <th>Photo</th>
                    <th>Check In</th>
                    <th>Check Out</th>
                    <th>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {visits.map((v) => {
                    const checkIn = new Date(v.checkInAt);
                    const checkOut = v.checkOutAt ? new Date(v.checkOutAt) : null;
                    const duration = checkOut ? `${Math.round((checkOut - checkIn) / 60000)} min` : "In progress";
                    return (
                      <tr key={v.visitId}>
                        <td>{v.visitId.substring(0, 8)}...</td>
                        <td>{v.vendorName || "-"}</td>
                        <td>
                          {v.checkInPhotoUrl && (
                            <img
                              src={`${API_BASE}${v.checkInPhotoUrl}`}
                              alt="check-in"
                              className="thumbnail"
                              onClick={() => window.open(`${API_BASE}${v.checkInPhotoUrl}`)}
                              title="Click to view"
                            />
                          )}
                        </td>
                        <td>{checkIn.toLocaleTimeString()}</td>
                        <td>{checkOut ? checkOut.toLocaleTimeString() : "-"}</td>
                        <td>{duration}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === "export" && (
        <div className="section-card">
          <h2>Export Data & Security</h2>
          <div className="button-row wrap">
            <button onClick={() => exportData("csv")} className="button info">
              📥 Download as CSV
            </button>
            <button onClick={() => exportData("geojson")} className="button warning">
              📥 Download as GeoJSON
            </button>
            <button onClick={exportPublicKeyPEM} className="button purple">
              🔑 Export Public Key (PEM)
            </button>
          </div>
          <p className="note-text">
            ✓ Data is immutable and cryptographically signed with persistent device keys.<br />
            ✓ Each entry includes photo proof, GPS location (±{ACCURACY_THRESHOLD}m), and timestamp.<br />
            ✓ Device public key exported for verification and audit trail.
          </p>
        </div>
      )}

      {modal.open && (
        <div className="modal-overlay" role="dialog" aria-modal="true">
          <div className="modal">
            <h3 className="modal-title">{modal.title}</h3>
            <p className="modal-message">{modal.message}</p>
            <div className="modal-actions">
              {modal.cancelLabel && (
                <button className="button ghost" onClick={() => closeModal(false)}>
                  {modal.cancelLabel}
                </button>
              )}
              <button className="button primary" onClick={() => closeModal(true)}>
                {modal.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
