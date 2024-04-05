async function generateKeypair() {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
    
    const publicKeyExported = await crypto.subtle.exportKey("spki", publicKey);
    const privateKeyExported = await crypto.subtle.exportKey("pkcs8", privateKey);
    
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyExported)));
    const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyExported)));
    
    return {
        publicKey: publicKeyBase64,
        privateKey: privateKeyBase64,
    };
}

async function encryptData(data, publicKey) {
    const publicKeyImported = await crypto.subtle.importKey(
        "spki",
        new Uint8Array(atob(publicKey).split("").map((c) => c.charCodeAt(0))),
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );
    
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        publicKeyImported,
        new TextEncoder().encode(data)
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
}

async function decryptData(encryptedData, privateKey) {
    const privateKeyImported = await crypto.subtle.importKey(
        "pkcs8",
        new Uint8Array(atob(privateKey).split("").map((c) => c.charCodeAt(0))),
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );
    
    const decryptedData = await crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        privateKeyImported,
        new Uint8Array(atob(encryptedData).split("").map((c) => c.charCodeAt(0)))
    );
    
    return new TextDecoder().decode(decryptedData);
}


async function onEncrypt() {
    try {
        const publicKey = document.getElementById("publicKey").value;
        const data = document.getElementById("encryptData").value;
        const encrypted = await encryptData(data, publicKey);
        document.getElementById("encryptResult").textContent = encrypted;
    } catch (err) {
        alert("Invalid public key");
    }
}

async function onDecrypt() {
    try {
        const privateKey = document.getElementById("privateKey").value;
        const data = document.getElementById("decryptData").value;
        const decrypted = await decryptData(data, privateKey);
        document.getElementById("decryptResult").textContent = decrypted;
    } catch (err) {
        alert("Invalid or wrong private key");
    }
}

async function onKeyGen() {
    const keypair = await generateKeypair();
    document.getElementById("generatedPrivateKey").textContent = keypair.privateKey;
    document.getElementById("generatedPublicKey").textContent = keypair.publicKey;
}