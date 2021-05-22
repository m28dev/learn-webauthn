const express = require('express');
const path = require('path');
const session = require('express-session');

const cbor = require('cbor');
const crypto = require('crypto');
const jsrsasign = require('jsrsasign');
const base64url = require('base64url');

// express
const app = express();
const port = 3000;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.COOKIE_SECRET || 'A2ey6LdvDg5NRrvC',
  resave: false,
  saveUninitialized: false,
//  proxy: true,
  cookie: { secure: auto }
}));

// credential storage
const storage = new Map();

/* home page */
app.get('/', (req, res) => {
  // TODO
  res.render('index');
});

/* registration-start: 鍵の登録を開始する */
app.post('/registration-start', (req, res) => {
  // TODO ユーザー名とか受け取る
  // TODO 定数にする → RP ID, alg

  // ユーザーIDを生成
  const id = crypto.randomUUID();

  // チャレンジを生成
  // TODO 保存する
  const challenge = randomBytes(16).toString('hex');

  // PublicKeyCredentialCreationOptionsを生成
  const options = {
    rp: {
      id: "learn-webauthn"
    },
    user: {
      id,
      displayName: "msy",
      name: "msy"
    },
    challenge,
    pubKeyCredParams: [
      {
        alg: -257,
        type: "public-key"
      },
      {
        alg: -7,
        type: "public-key"
      }
    ],
    timeout: 360000,
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred"
    },
    attestation: "none"
  }

  res.json({ options });
});

/* registration: 鍵を登録する */
app.post('/registration', (req, res) => {
  const attestationObject = Buffer.from(req.body.response.attestationObject, 'base64');
  const JSONtext = Buffer.from(req.body.response.clientDataJSON, 'base64').toString('utf8');
  const C = JSON.parse(JSONtext);

  // `C.type`の値が`webauthn.create`かどうか確認
  if (C.type !== "webauthn.create") {
    throw new Error('C.type is not "webauthn.create"');
  }

  // `C.challenge`が`options.challenge`をbase64urlエンコードしたものと一致するか確認
  // TODO challengeが固定値
  if (C.challenge !== base64url.encode("randomString")) {
    throw new Error('C.challenge does not match');
  }

  // `C.origin`がRPのオリジンと一致するか確認
  // TODO オリジンがハードコードされている
  if (C.origin !== "http://localhost:3000") {
    throw new Error('C.origin does not match');
  }

  // TODO attestation関連

  // attestationObjectをCBORデコード
  const decodedAttestationObject = cbor.decodeAllSync(attestationObject)[0];
  let authData = decodedAttestationObject.authData;

  /*
   * authDataは下記を参考に分解していく
   * https://www.w3.org/TR/webauthn-2/#authenticator-data
   */

  // rpIdHashを取得
  const rpIdHash = authData.slice(0, 32);
  authData = authData.slice(32);
  // rpIdHashが想定しているRP IDのSHA-256ハッシュか確認
  // TODO RP IDがハードコード
  const rpId = crypto.createHash('sha256').update("localhost").digest();
  if (!rpId.equals(rpIdHash)) {
    throw new Error('rpIdHash does not match the expected RP ID hash');
  }

  // flagsを取得
  const flags = authData.slice(0, 1).readUInt8(0);
  authData = authData.slice(1);

  // User Presentのフラグ（1bit目）が立っているか確認
  const up = !!(flags & 0x01);
  if (!up) {
    throw new Error('the user is not present');
  }

  // signCountを取得
  const signCount = authData.slice(0, 4);
  authData = authData.slice(4);

  // TODO Bit 6: Attested credential data included (AT). の確認もする？？
  // TODO これ以降、どこの何を取得しているのかコメントを残す（Attested credential dataのaaguidを取得してる。など）
  // https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data

  // aaguidを取得
  const aaguid = authData.slice(0, 16);
  authData = authData.slice(16);

  // credentialIdLengthを取得
  const credentialIdLength = authData.slice(0, 2).readUInt16BE(0);
  authData = authData.slice(2);

  // credentialIdを取得
  const credentialId = authData.slice(0, credentialIdLength);
  authData = authData.slice(credentialIdLength);

  // credentialPublicKeyを取得
  const credentialPublicKey = cbor.decodeAllSync(authData)[0];

  // algが鍵の作成時に`options.pubKeyCredParams`で指定したものになっているか確認する
  // TODO 判定するalgがハードコード
  const alg = credentialPublicKey.get(3);
  if (alg != -7 && alg != -257) {
    throw new Error('alg does not match');
  }

  // TODO Extensionsは無視していることをコメントに残す？

  // TODO 18. のfmt判定は後で

  // TODO コメント書く → 今回はサンプルなので鍵をそのまま登録する
  // 手順.22に従い、同じ鍵が別のユーザーに登録されていないか確認する必要あり

  // ユーザーと鍵を登録する
  // credentialPublicKeyをJWKの形式に変換して保存する
  // TODO RS256にしか対応していない
  const pubkeyJwk = {
    kty: "RSA",
    n: base64url.encode(credentialPublicKey.get(-1)),
    e: base64url.encode(credentialPublicKey.get(-2))
  }

  // TODO ユーザーIDが固定
  // TODO 保存する内容これでOK？ よむ： https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user
  storage.set('cc8faa1e-4434-4ec8-a040-b7f80ad43c27', {
    name: 'msy',
    displayName: 'msy',
    credentials: [{ // TODO 上書きしちゃってる…2つ登録したときの挙動ってどうなるんだっけ
      credentialId: credentialId.toString('base64'),
      credentialPublicKey: pubkeyJwk,
      signCount: signCount.readUInt16BE(0)
    }]
  }); // TODO transports も保存したほうがいいかな？

  // TODO debug
  console.log(credentialPublicKey);
  console.log(storage.get('cc8faa1e-4434-4ec8-a040-b7f80ad43c27'));

  // 登録完了
  res.sendStatus(200);
});

/* authentication-start: 認証開始 */
app.post('/authentication-start', (req, res) => {
  // TODO 保存する
  const challenge = randomBytes(16).toString('hex');
  const timeout = 120000;
  // TODO そのユーザーのクレデンシャルを返す
  const allowCredentials = [{
    type: 'public-key',
    id: 'cc8faa1e-4434-4ec8-a040-b7f80ad43c27'
  }];
  // TODO allowCredentialsがない場合はrequiredではないか？
  const userVerification = 'preferred';
  const options = { challenge, timeout, allowCredentials, userVerification }

  // TODO
  const credentialId = storage.get('cc8faa1e-4434-4ec8-a040-b7f80ad43c27').credentials[0].credentialId;
  res.send({
    credentialId
  });
});

/* authentication: 認証する */
app.post('/authentication', (req, res) => {
  // TODO debug → user.idになる
  console.log('userHandle: ', Buffer.from(req.body.response.userHandle, 'base64').toString());

  // TODO
  // - 手順.5 options.allowCredentialsで渡した中にあったcredential.idか確認
  // - 手順.6 ユーザーがcredential.idの持ち主か？
  // - 手順.7 credential.idから対応した公開鍵を見つけてくる
  // - 鍵とユーザーの情報をどう持たせるか決めてからやる
  const credentialId = req.body.credential.id;

  // responseの内容を取得
  const cData = Buffer.from(req.body.response.clientDataJSON, 'base64');
  const authData = Buffer.from(req.body.response.authenticatorData, 'base64');
  const sig = Buffer.from(req.body.response.signature, 'base64');

  const JSONtext = cData.toString('utf-8');
  const C = JSON.parse(JSONtext);

  // `C.type`の値が`webauthn.get`かどうか確認
  if (C.type !== "webauthn.get") {
    throw new Error('C.type is not "webauthn.get"');
  }

  // `C.challenge`が`options.challenge`をbase64urlエンコードしたものと一致するか確認
  // TODO challengeが固定値
  if (C.challenge !== base64url.encode("randomString")) {
    throw new Error('C.challenge does not match');
  }

  // `C.origin`がRPのオリジンと一致するか確認
  // TODO オリジンがハードコードされている
  if (C.origin !== "http://localhost:3000") {
    throw new Error('C.origin does not match');
  }

  // rpIdHashを取得
  const rpIdHash = authData.slice(0, 32);
  // rpIdHashが想定しているRP IDのSHA-256ハッシュか確認
  // TODO RP IDがハードコード
  const rpId = crypto.createHash('sha256').update("localhost").digest();
  if (!rpId.equals(rpIdHash)) {
    throw new Error('rpIdHash does not match the expected RP ID hash');
  }

  // flagsを取得
  const flags = authData.slice(32, 33).readUInt8(0);
  // User Presentのフラグ（1bit目）が立っているか確認
  const up = !!(flags & 0x01);
  if (!up) {
    throw new Error('the user is not present');
  }

  // signCountを取得
  const signCount = authData.slice(33, 37).readUInt32BE(0);

  // TODO debug
  console.log('signCount: ', signCount);

  // 署名検証
  const hash = crypto.createHash('sha256').update(cData).digest();
  // TODO ユーザーID固定、credentials複数あるときは？
  const credentialPublicKey = storage.get('cc8faa1e-4434-4ec8-a040-b7f80ad43c27').credentials[0].credentialPublicKey;

  // TODO alg固定
  const signature = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
  signature.init(credentialPublicKey);
  signature.updateHex(Buffer.concat([authData, hash]).toString('hex'));

  const isValid = signature.verify(sig.toString('hex'));
  if (!isValid) {
    throw new Error('Signature validation failed');
  }

  // signCountを更新
  // TODO credentials複数のとき
  const storedSignCount = storage.get('cc8faa1e-4434-4ec8-a040-b7f80ad43c27').credentials[0].signCount;

  // signCountが前回のsignCountと同じ、もしくは少ない場合はクローンされた認証器の利用が疑われる。エラーにしとく
  if ((signCount !== 0 || storedSignCount !== 0) &&
    (signCount == storedSignCount || signCount < storedSignCount)) {
    throw new Error('signCount is invalid');
  }

  // TODO debug
  console.log('storedSignCount: ', storedSignCount);

  // 問題なければ`authData.signCount`で更新
  const credentials = storage.get('cc8faa1e-4434-4ec8-a040-b7f80ad43c27').credentials[0];
  credentials.signCount = signCount;

  // TODO debug
  console.log(storage.get('cc8faa1e-4434-4ec8-a040-b7f80ad43c27'));

  res.sendStatus(200);
});

/* welcome: ログイン後のページ */
app.get('/welcome', (req, res) => {
  // TODO
  const user = { username: 'testtest' };
  res.render('welcome', { user });
});

// Starts the HTTP server listening for connections.
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
