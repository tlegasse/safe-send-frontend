document.addEventListener("DOMContentLoaded", () => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = document.getElementById("key")
    const raw = document.getElementById("raw")
    const decryptSubmit = document.getElementById("decrypt-submit")
    const encrypted = document.getElementById("encrypted")
    const salt = new Date().getTime()
    const encoder = new TextEncoder();
    const decoder = new TextDecoder("utf-8");
    const randomPass = window.crypto.getRandomValues(new Uint8Array(12));

    const triggerEncryption = async () => {
        const derivedKey = await deriveKey(key.value, salt)
        const payload = raw.value
        const encryptedPayload = await getEncryptedPayload(payload, derivedKey)

        encrypted.value = JSON.stringify({
            keyStr: key.value,
            salt: salt,
            iv: btoa(String.fromCharCode(...iv)),
            payload: encryptedPayload
        })
    }

    const triggerDecryption = async () => {
        const encryptedStr = encrypted.value
        const { keyStr, salt, iv: ivBase64, payload } = JSON.parse(encryptedStr)
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
        const derivedKey = await deriveKey(keyStr, salt)

        getDecryptedPayload(derivedKey, iv, payload)
    }

    const deriveKey = async (password, salt) => {
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: encoder.encode(salt.toString()), // Store this with your data
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    };

    const getEncryptedPayload = async (payload, derivedKey) => {
        const encodedPayload = encoder.encode(payload);

        const encryptedPayload = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            derivedKey,
            encodedPayload
        );

        let buffer = new Uint8Array(encryptedPayload, 0, encryptedPayload.byteLength);
        const base64 = btoa(String.fromCharCode(...buffer));
        return base64
    }

    const getDecryptedPayload = async (derivedKey, iv, payload) => {
        payload = Uint8Array.from(atob(payload), c => c.charCodeAt(0));

        let decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv
            },
            derivedKey,
            payload.buffer
        );

        const arr = new Uint8Array(decrypted)
        return decoder.decode(arr)
    }

    key.value = salt + randomPass

    raw.addEventListener("change", () => triggerEncryption())
    encrypted.addEventListener("change", () => triggerDecryption())

    triggerEncryption()

    decryptSubmit.addEventListener("click", () => triggerDecryption())
})
