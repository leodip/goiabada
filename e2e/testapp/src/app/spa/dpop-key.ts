// Add sign-in to a SPA or mobile app, "Bind the tokens to a key with DPoP", step 1: the SPA's DPoP
// key pair, made by the browser with its private key non-extractable, so no script can read it, and
// kept in IndexedDB, which stores the key itself, across the trip to the auth server and for as long
// as the refresh token it's bound to.

const database = "testapp-spa-dpop";
const store = "keys";
const name = "dpop";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(database, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(store);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function run<T>(mode: IDBTransactionMode, act: (keys: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = act(db.transaction(store, mode).objectStore(store));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

export const loadKey = () => run<CryptoKeyPair | undefined>("readonly", (keys) => keys.get(name));
export const saveKey = (pair: CryptoKeyPair) => run("readwrite", (keys) => keys.put(pair, name));
export const forgetKey = () => run("readwrite", (keys) => keys.delete(name));

// The public key as a proof's jwk header member carries it, for the page to show.
export async function publicJwk(pair: CryptoKeyPair) {
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { kty, crv, x, y };
}
