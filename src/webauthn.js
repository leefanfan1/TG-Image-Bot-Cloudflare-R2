// WebAuthn / PassKey support for admin panel
// Implements registration and authentication using Web Authentication API

// --- CBOR decoder (minimal, for COSE key parsing) ---

function decodeCBOR(buffer) {
  const dv = new DataView(buffer);
  let offset = 0;

  function decodeItem() {
    if (offset >= buffer.byteLength) throw new Error('CBOR: unexpected end');
    const initial = dv.getUint8(offset++);
    const majorType = initial >> 5;
    let info = initial & 0x1f;

    if (info === 24) { info = dv.getUint8(offset++); }
    else if (info === 25) { info = dv.getUint16(offset); offset += 2; }
    else if (info === 26) { info = dv.getUint32(offset); offset += 4; }
    else if (info === 27) { offset += 8; info = 0; }

    switch (majorType) {
      case 0: return info;
      case 1: return -1 - info;
      case 2: {
        const bytes = new Uint8Array(buffer.slice(offset, offset + info));
        offset += info;
        return bytes;
      }
      case 3: {
        const str = new TextDecoder().decode(buffer.slice(offset, offset + info));
        offset += info;
        return str;
      }
      case 4: {
        const arr = [];
        for (let i = 0; i < info; i++) arr.push(decodeItem());
        return arr;
      }
      case 5: {
        const map = {};
        for (let i = 0; i < info; i++) {
          const k = decodeItem();
          const v = decodeItem();
          map[k] = v;
        }
        return map;
      }
      case 6: return decodeItem(); // tag — skip and decode next
      default: throw new Error(`CBOR type ${majorType} not implemented`);
    }
  }

  return decodeItem();
}

// --- Base64url helpers ---

function toBase64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// --- COSE key parsing (ES256/P-256) ---

function parseCOSEKey(coseBytes) {
  const key = decodeCBOR(coseBytes.buffer || coseBytes);

  // Check it's EC2 (kty=2) with ES256 (alg=-7) on P-256 (crv=1)
  if (key[1] !== 2) throw new Error('Only EC2 keys supported');
  if (key[3] !== -7) throw new Error('Only ES256 (-7) algorithm supported');
  if (key[-1] !== 1) throw new Error('Only P-256 curve supported');

  const x = key[-2];
  const y = key[-3];
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new Error('Invalid COSE key coordinates');
  }

  // Build raw public key as uncompressed point (0x04 + x + y)
  const rawKey = new Uint8Array(1 + x.length + y.length);
  rawKey[0] = 0x04;
  rawKey.set(x, 1);
  rawKey.set(y, 1 + x.length);

  return rawKey;
}

// --- Parse authenticator data ---

function parseAuthData(authData) {
  const dv = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  let pos = 0;

  const rpIdHash = authData.slice(pos, pos + 32); pos += 32;
  const flags = dv.getUint8(pos++);
  const counter = dv.getUint32(pos); pos += 4;

  const up = !!(flags & 0x01);
  const uv = !!(flags & 0x04);
  const at = !!(flags & 0x40);

  let attestedCredentialData = null;

  if (at) {
    const aaguid = authData.slice(pos, pos + 16); pos += 16;
    const credIdLen = dv.getUint16(pos); pos += 2;
    const credId = authData.slice(pos, pos + credIdLen); pos += credIdLen;

    // COSE key is CBOR-encoded. decodeCBOR reads only the first top-level
    // CBOR item, so any trailing extension bytes are safely ignored.
    const coseKeyEncoded = authData.slice(pos);
    const publicKeyRaw = parseCOSEKey(coseKeyEncoded);

    attestedCredentialData = { aaguid, credId, publicKey: publicKeyRaw };
  }

  return { rpIdHash, flags, counter, up, uv, attestedCredentialData };
}

// --- Registration ---

export async function beginRegistration(domain) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  return {
    challenge: toBase64url(challenge),
    rp: { name: '图床管理', id: domain },
    user: {
      id: toBase64url(userId),
      name: 'admin',
      displayName: '管理员',
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256
      { type: 'public-key', alg: -257 },  // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'required',
    },
    attestation: 'none',
    timeout: 60000,
  };
}

export async function completeRegistration(env, response, domain) {
  const { id, rawId, response: clientResp } = response;

  if (!rawId || !clientResp) throw new Error('Invalid registration response');

  const rawIdBytes = fromBase64url(rawId);

  // Decode clientDataJSON
  const clientData = JSON.parse(new TextDecoder().decode(fromBase64url(clientResp.clientDataJSON)));

  // Verify type
  if (clientData.type !== 'webauthn.create') {
    throw new Error('Wrong WebAuthn type: ' + clientData.type);
  }

  // Verify origin
  if (clientData.origin !== `https://${domain}` && clientData.origin !== `http://localhost:8787`) {
    throw new Error('Invalid origin: ' + clientData.origin);
  }

  // Verify challenge was issued by this server
  const challengeB64 = clientData.challenge;
  const storedChallenge = await env.IMG_KV.get(`wa:reg:${challengeB64}`);
  if (!storedChallenge) {
    throw new Error('Registration challenge not found or expired');
  }
  await env.IMG_KV.delete(`wa:reg:${challengeB64}`);

  // Decode attestationObject
  const attObj = fromBase64url(clientResp.attestationObject);
  const parsedAtt = decodeCBOR(attObj.buffer || attObj);

  const fmt = parsedAtt.fmt;
  const authData = parsedAtt.authData;

  if (!(authData instanceof Uint8Array)) throw new Error('Invalid authData');

  // Build SPKI-wrapped ECDSA P-256 public key from raw uncompressed point
function buildSpkiEcPublicKey(rawPoint) {
  const EC_OID = new Uint8Array([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
  const P256_OID = new Uint8Array([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
  const algIdContent = new Uint8Array(EC_OID.length + P256_OID.length);
  algIdContent.set(EC_OID, 0);
  algIdContent.set(P256_OID, EC_OID.length);

  const algId = new Uint8Array([0x30, algIdContent.length, ...algIdContent]);
  const bitString = new Uint8Array([0x03, rawPoint.length + 1, 0x00, ...rawPoint]);
  const spkiContent = new Uint8Array(algId.length + bitString.length);
  spkiContent.set(algId, 0);
  spkiContent.set(bitString, algId.length);

  const spki = new Uint8Array(spkiContent.length + (spkiContent.length > 127 ? 3 : 2));
  spki[0] = 0x30;
  spki[1] = spkiContent.length;
  spki.set(spkiContent, 2);
  return spki;
}

// Parse authenticator data to extract credential
  const parsed = parseAuthData(authData);
  if (!parsed.attestedCredentialData) throw new Error('No attested credential data');

  const { credId, publicKey } = parsed.attestedCredentialData;

  // Wrap raw public key in SPKI format for browser crypto.subtle compatibility
  const spkiKey = buildSpkiEcPublicKey(publicKey);

  // Store credential in KV
  const credIdB64 = toBase64url(credId);
  const credential = {
    credId: credIdB64,
    publicKey: toBase64url(spkiKey),
    counter: parsed.counter,
    transports: response.response?.transports || [],
    createdAt: Date.now(),
  };

  await env.IMG_KV.put(`wa:cred:${credIdB64}`, JSON.stringify(credential));

  return credIdB64;
}

// --- Authentication ---

export async function beginAuthentication(env) {
  // List all credentials
  const list = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  if (list.keys.length === 0) return null;

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const challengeB64 = toBase64url(challenge);

  // Store challenge for verification
  await env.IMG_KV.put(`wa:auth:${challengeB64}`, 'pending', { expirationTtl: 300 });

  const allowCredentials = list.keys.map(k => ({
    id: k.name.replace('wa:cred:', ''),
    type: 'public-key',
    transports: ['internal'],
  }));

  return {
    challenge: challengeB64,
    allowCredentials,
    userVerification: 'required',
    timeout: 60000,
  };
}

export async function completeAuthentication(env, response, domain) {
  const { id, rawId, response: clientResp } = response;
  if (!rawId || !clientResp) throw new Error('Invalid auth response');

  const rawIdBytes = fromBase64url(rawId);
  const credIdB64 = toBase64url(rawIdBytes);

  // Get stored credential
  const storedJson = await env.IMG_KV.get(`wa:cred:${credIdB64}`);
  if (!storedJson) throw new Error('Credential not found');

  const stored = JSON.parse(storedJson);

  // Decode clientDataJSON
  const clientData = JSON.parse(new TextDecoder().decode(fromBase64url(clientResp.clientDataJSON)));

  // Verify type
  if (clientData.type !== 'webauthn.get') {
    throw new Error('Wrong WebAuthn type: ' + clientData.type);
  }

  // Verify origin
  if (clientData.origin !== `https://${domain}` && clientData.origin !== `http://localhost:8787`) {
    throw new Error('Invalid origin: ' + clientData.origin);
  }

  // Verify challenge exists
  const challengeB64 = clientData.challenge;
  const storedChallenge = await env.IMG_KV.get(`wa:auth:${challengeB64}`);
  if (!storedChallenge) throw new Error('Challenge not found or expired');
  await env.IMG_KV.delete(`wa:auth:${challengeB64}`);

  // Decode authenticator data
  const authDataBytes = fromBase64url(clientResp.authenticatorData);
  const parsedAuth = parseAuthData(authDataBytes);

  // Check RP ID hash (SHA-256 of domain)
  const domainHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain));
  if (toBase64url(new Uint8Array(domainHash)) !== toBase64url(parsedAuth.rpIdHash)) {
    throw new Error('RP ID hash mismatch');
  }

  // Verify user presence
  if (!parsedAuth.up) throw new Error('User not present');

  // Build signature base string: authenticatorData + SHA-256(clientDataJSON)
  const clientDataHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientData)));
  const sigBase = new Uint8Array(authDataBytes.length + clientDataHash.byteLength);
  sigBase.set(authDataBytes, 0);
  sigBase.set(new Uint8Array(clientDataHash), authDataBytes.length);

  // Import stored public key
  const rawKey = fromBase64url(stored.publicKey);
  const publicKey = await crypto.subtle.importKey(
    'spki', rawKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['verify']
  );

  // Parse signature (WebAuthn returns DER-encoded ECDSA signature)
  const signatureBytes = fromBase64url(clientResp.signature);

  // Verify
  const isValid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signatureBytes,
    sigBase
  );

  if (!isValid) throw new Error('Signature verification failed');

  // Update counter
  stored.counter = parsedAuth.counter;
  await env.IMG_KV.put(`wa:cred:${credIdB64}`, JSON.stringify(stored));

  return true;
}

// --- List registered credentials ---

export async function listCredentials(env) {
  const list = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  const credentials = await Promise.all(
    list.keys.map(async (k) => {
      const val = await env.IMG_KV.get(k.name);
      if (!val) return null;
      try {
        const parsed = JSON.parse(val);
        return {
          id: k.name.replace('wa:cred:', ''),
          createdAt: parsed.createdAt,
        };
      } catch { return null; }
    })
  );
  return credentials.filter(Boolean);
}

// --- Delete credential ---

export async function deleteCredential(env, credId) {
  if (!/^[A-Za-z0-9_-]{10,100}$/.test(credId)) throw new Error('Invalid credential ID');
  await env.IMG_KV.delete(`wa:cred:${credId}`);
}
