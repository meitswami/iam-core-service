"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenCryptoService = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const crypto_1 = require("crypto");
function b64ToBuf(b64) {
    return Buffer.from(b64, 'base64');
}
function bufToB64(buf) {
    return buf.toString('base64');
}
let TokenCryptoService = class TokenCryptoService {
    config;
    key;
    constructor(config) {
        this.config = config;
        const keyB64 = this.config.get('TOKEN_ENC_KEY_B64', { infer: true });
        const key = b64ToBuf(keyB64);
        if (key.length !== 32)
            throw new Error('TOKEN_ENC_KEY_B64 must be 32 bytes base64 (AES-256-GCM key).');
        this.key = key;
    }
    encrypt(plain) {
        const iv = (0, crypto_1.randomBytes)(12);
        const cipher = (0, crypto_1.createCipheriv)('aes-256-gcm', this.key, iv);
        const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        const blob = { v: 1, alg: 'A256GCM', ivB64: bufToB64(iv), tagB64: bufToB64(tag), ctB64: bufToB64(ct) };
        return Buffer.from(JSON.stringify(blob), 'utf8').toString('base64');
    }
    decrypt(encB64) {
        const json = Buffer.from(encB64, 'base64').toString('utf8');
        const blob = JSON.parse(json);
        if (blob?.v !== 1 || blob?.alg !== 'A256GCM')
            throw new Error('Unsupported encrypted token blob.');
        const iv = b64ToBuf(blob.ivB64);
        const tag = b64ToBuf(blob.tagB64);
        const ct = b64ToBuf(blob.ctB64);
        const decipher = (0, crypto_1.createDecipheriv)('aes-256-gcm', this.key, iv);
        decipher.setAuthTag(tag);
        const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
        return pt.toString('utf8');
    }
};
exports.TokenCryptoService = TokenCryptoService;
exports.TokenCryptoService = TokenCryptoService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [config_1.ConfigService])
], TokenCryptoService);
//# sourceMappingURL=token-crypto.service.js.map