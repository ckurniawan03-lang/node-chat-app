const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
const users = new Map();

// Generate RSA key pair for signing & encryption
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

function signMessage(text) {
  return crypto.sign("sha256", Buffer.from(text), privateKey).toString("hex");
}

function verifySignature(text, signatureHex, senderPublicKeyPem) {
  try {
    const senderPublicKey = crypto.createPublicKey(senderPublicKeyPem);
    const signatureBuffer = Buffer.from(signatureHex, "hex");
    return crypto.verify("sha256", Buffer.from(text), senderPublicKey, signatureBuffer);
  } catch (err) {
    return false;
  }
}

function encryptForTarget(text, targetPublicKeyPem) {
  const targetPublicKey = crypto.createPublicKey(targetPublicKeyPem);
  return crypto.publicEncrypt(targetPublicKey, Buffer.from(text)).toString("hex");
}

function decryptWithOwnPrivateKey(ciphertextHex) {
  try {
    const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(ciphertextHex, "hex"));
    return decrypted.toString("utf8");
  } catch (err) {
    return null;
  }
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);

    socket.emit("registerPublicKey", {
      username,
      publicKey,
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;
        if ((match = message.match(/^!secret (\w+)$/))) {
          const requestedTarget = match[1];
          if (!users.has(requestedTarget)) {
            console.log(`User ${requestedTarget} not found`);
          } else {
            targetUsername = requestedTarget;
            console.log(`Now secretly chatting with ${targetUsername}`);
          }
        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
        } else {
          let messageBody = message;
          let mode = "PLAIN";

          if (targetUsername) {
            const targetPublicKey = users.get(targetUsername);
            if (targetPublicKey) {
              messageBody = encryptForTarget(message, targetPublicKey);
              mode = "SECRET";
            }
          }

          const signature = signMessage(messageBody);
          const payload = `${mode}::${messageBody}::${signature}`;
          socket.emit("message", { username, message: payload });
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUsername, publicKey: newPublicKey } = data;
  users.set(newUsername, newPublicKey);
  console.log(`${newUsername} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: incomingPayload } = data;
  if (senderUsername !== username) {
    const parts = incomingPayload.split("::");
    const senderPublicKey = users.get(senderUsername);

    if (parts.length !== 3 || !senderPublicKey) {
      console.log(`${senderUsername}: ${incomingPayload}`);
      console.log("⚠️ Warning: the message may have been changed or sender is unverified");
    } else {
      const [mode, messageBody, signatureHex] = parts;
      const isAuthentic = verifySignature(messageBody, signatureHex, senderPublicKey);

      if (!isAuthentic) {
        console.log(`${senderUsername}: ${messageBody}`);
        console.log("⚠️ Warning: the message may have been changed or this user is fake");
      } else if (mode === "SECRET") {
        const decryptedText = decryptWithOwnPrivateKey(messageBody);
        if (decryptedText !== null) {
          console.log(`${senderUsername} (secret): ${decryptedText}`);
        } else {
          console.log(`${senderUsername}: ${messageBody}`);
        }
      } else {
        console.log(`${senderUsername}: ${messageBody}`);
      }
    }
    rl.prompt();
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});