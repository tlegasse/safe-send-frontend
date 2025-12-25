document.addEventListener("DOMContentLoaded", () => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = document.getElementById("key")
    const raw = document.getElementById("raw")
    const decryptSubmit = document.getElementById("decrypt-submit")
    const encrypted = document.getElementById("encrypted")
    const salt = new Date().getTime()

    const triggerEncryption = async () => {
        const derivedKey = await deriveKey(key.value, salt)
        const payload = raw.value
        const encryptedPayload = await getEncryptedPayload(payload, derivedKey)

        encrypted.value = JSON.stringify({
            keyStr: key.value,
            salt: salt,
            iv: iv,
            payload: encryptedPayload
        })
    }

    const triggerDecryption = async () => {
        const encryptedStr = encrypted.value
        const { keyStr, salt, iv, payload } = JSON.parse(encryptedStr)

        decrypt(keyStr, salt, iv, payload)
    }

    const deriveKey = async (password, salt) => {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: enc.encode(salt), // Store this with your data
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
        const enc = new TextEncoder();
        const encodedPayload = enc.encode(payload);

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

    async function decryptMessage(key) {
        let decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            ciphertext
        );

        let dec = new TextDecoder();
        const decryptedValue = document.querySelector(".aes-gcm .decrypted-value");
        decryptedValue.classList.add('fade-in');
        decryptedValue.addEventListener('animationend', () => {
            decryptedValue.classList.remove('fade-in');
        }, { once: true });
        decryptedValue.textContent = dec.decode(decrypted);
    }
    const decrypt = (keyStr, salt, iv, payload) => {
        const buffer = Uint8Array.from(atob(payload), c => c.charCodeAt(0));

        const enc = new TextEncoder();
        const encodedPayload = enc.encode(payload);

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

    key.value = salt + key.value

    raw.addEventListener("change", () => triggerEncryption())
    encrypted.addEventListener("change", () => triggerDecryption())

    triggerEncryption()

    decryptSubmit.addEventListener("click", () => triggerDecryption())
})
