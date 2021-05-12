// 鍵の登録を開始
async function registration() {
    // TODO
    const options = {
        rp: {
            name: "learn-webauthn",
            // id: "learn-webauthn.aoiro27go.xyz"
        },
        user: {
            id: Uint8Array.from("cc8faa1e-4434-4ec8-a040-b7f80ad43c27", c => c.charCodeAt(0)),
            name: "msy", // twiterアカウント名 @xxxx
            displayName: "msy", // twitter表示名 yyy みたいな関係性？
        },
        challenge: Uint8Array.from('randomString', c => c.charCodeAt(0)),
        pubKeyCredParams: [{ alg: -257, type: "public-key" }, { alg: -7, type: "public-key" }],
        timeout: 360000,
        /*
                authenticatorSelection: {
                    residentKey: "required",
                    requireResidentKey: true,
                    userVerification: "required"
                },
        */
        attestation: "none"
    };

    const credential = await navigator.credentials.create({ publicKey: options });

    // 登録する鍵を送る
    const result = await fetch('/registration', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            response: {
                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
            }
        })
    });
    console.log(result);
}

// 認証を開始
async function authentication() {
    // TODO
    const op = await fetch('/authentication-start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: 'msy'
        })
    }).then(response => response.json());

    const options = {
        challenge: Uint8Array.from('randomString', c => c.charCodeAt(0)),
        allowCredentials: [{
            type: "public-key",
            id: Uint8Array.from(atob(op.credentialId), c => c.charCodeAt(0))
        }]
    }

    const credential = await navigator.credentials.get({ publicKey: options });

    // 認証する
    const result = await fetch('/authentication', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            credential: {
                id: op.credentialId
            },
            response: {
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                userHandle: btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle)))
            }
        })
    });
    console.log(result);
}

// イベントハンドラ登録
const regBtn = document.getElementById('reg');
regBtn.addEventListener('click', registration);

const authBtn = document.getElementById('auth');
authBtn.addEventListener('click', authentication);
