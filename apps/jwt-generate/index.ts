import { JSON } from "@klave/sdk";
import { CreateWalletInput, AddUserInput, GenerateKeyInput, ListKeysInput, RemoveKeyInput, RemoveUserInput, ImportKeyInput, KeyInput, JWTGenerateInput, JWTHeader, JWTCheckInput} from "./wallet/inputs/types";
import { Wallet } from "./wallet/wallet";
import { emit, revert } from "./klave/types";
import { encode, decode } from 'as-base64/assembly';

/**
 * @transaction add a key to the wallet
 * @param input containing the following fields:
 * - description: string
 * - type: string
 * @returns success boolean
 */
export function generateKey(input: GenerateKeyInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.generateKey(input.description, input.algorithm)) {
        wallet.save();
    }
}

/**
 * @transaction remove a key from the wallet
 * @param input containing the following fields:
 * - keyId: string
 * @returns success boolean
 */
export function removeKey(input: RemoveKeyInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.removeKey(input.keyId)) {
        wallet.save();
    }
}

/**
 * @transaction import a private key to the wallet
 * @param input containing a jwt string with a payload containing the following fields:
 * - description: string
 * - key: KeyInput
 * @returns success boolean
 */
export function importKey(input: ImportKeyInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    wallet.importKey(input.description, input.key.format, input.key.keyData, input.key.algorithm, input.key.extractable, input.key.usages);
    wallet.save();
}


/**
 * @query list all keys in the wallet
 * @param input containing the following fields:
 * - user: string, the user to list the keys for (optional)
 * @returns the list of keys
 */
export function listKeys(input: ListKeysInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    wallet.listKeys(input.user);
}

/**
 * @transaction add a user to the wallet
 * @param input containing the following fields:
 * - userId: string
 * - role: string, "admin" or "user"
 * @returns success boolean
 */
export function addUser(input: AddUserInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.addUser(input.userId, input.role, false)) {
        wallet.save();
    }
}

/**
 * @transaction remove a user from the wallet
 * @param input containing the following fields:
 * - userId: string
 * @returns success boolean
 */
export function removeUser(input: RemoveUserInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.removeUser(input.userId)) {
        wallet.save();
    }
}

/**
 * @transaction initialize the wallet
 * @param input containing the following fields:
 * - name: string
 * @returns success boolean
 */
export function createWallet(input: CreateWalletInput): void {
    let existingWallet = Wallet.load();
    if (existingWallet) {
        revert(`Wallet does already exists.`);
        return;
    }
    let wallet = new Wallet();
    wallet.create(input.name);
    wallet.save();
}


/**
 * @query generate a jwt token
 * @param input containing the following fields:
 * - payload: string
 * - keyId: string
 * @returns the jwt token
 */
export function generateJWT(input: JWTGenerateInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }

    let header = new JWTHeader();
    header.alg = "ECDSA";
    
    let h: Uint8Array = Uint8Array.wrap(String.UTF8.encode(JSON.stringify(header), true));
    let headerB64 = encode(h);
    let p: Uint8Array = Uint8Array.wrap(String.UTF8.encode(input.payload, true));
    let payloadB64 = encode(p);

    let jwtPayload = headerB64 + "." + payloadB64;

    emit("Generating JWT: " + jwtPayload + " - with key: " + input.keyId);

    let jwtSignature = wallet.sign(input.keyId, jwtPayload);
    if (jwtSignature == null) {
        revert("Failed to generate JWT");
        return;
    }
    
    let jwt = jwtPayload + "." + jwtSignature;

    emit("JWT generated: " + jwt);
}

/**
 * @query check the validity of a jwt token
 * @param input containing the following fields:
 * - jwt: string
 * - keyId: string
 * @returns success boolean
 */
export function checkJWT(input: JWTCheckInput): void {
    let items = input.jwt.split(".");
   if (items.length != 3) {
       revert("Invalid JWT format");
       return;
   }

   let wallet = Wallet.load();
   if (!wallet) {
       return;
   }
   let jwtHeaderU8 = decode(items[0]);
   let jwtHeaderStr: string = String.UTF8.decode(jwtHeaderU8.buffer, true);
   jwtHeaderStr = jwtHeaderStr.replace("\\", "");
   emit("jwtHeaderStr: " + jwtHeaderStr);
   let jwtPayloadU8 = decode(items[1]);
   let jwtPayloadStr: string = String.UTF8.decode(jwtPayloadU8.buffer, true);
   jwtPayloadStr = jwtPayloadStr.replace("\\", "");
   emit("jwtPayloadStr: " + jwtPayloadStr);

//    let jwtHeader : JWTHeader = JSON.parse<JWTHeader>(jwtHeaderStr);
//    emit("jwtHeader: " + jwtHeader.alg + " - " + items[0] + "." + items[1] + " - " + items[2]);

   if (!wallet.verify(input.keyId, items[0] + "." + items[1], items[2])) {
       revert("Invalid JWT signature");
       return;
   }    
   emit("Verification Successful");   
}
