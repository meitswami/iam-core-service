import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import type { Env } from '../config/env.schema';

type EncBlob = {
  v: 1;
  alg: 'A256GCM';
  ivB64: string;
  tagB64: string;
  ctB64: string;
};

function b64ToBuf(b64: string) {
  return Buffer.from(b64, 'base64');
}

function bufToB64(buf: Buffer) {
  return buf.toString('base64');
}

@Injectable()
export class TokenCryptoService {
  private readonly key: Buffer;

  constructor(private readonly config: ConfigService<Env, true>) {
    const keyB64 = this.config.get('TOKEN_ENC_KEY_B64', { infer: true });
    const key = b64ToBuf(keyB64);
    if (key.length !== 32) throw new Error('TOKEN_ENC_KEY_B64 must be 32 bytes base64 (AES-256-GCM key).');
    this.key = key;
  }

  encrypt(plain: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const blob: EncBlob = { v: 1, alg: 'A256GCM', ivB64: bufToB64(iv), tagB64: bufToB64(tag), ctB64: bufToB64(ct) };
    return Buffer.from(JSON.stringify(blob), 'utf8').toString('base64');
  }

  decrypt(encB64: string): string {
    const json = Buffer.from(encB64, 'base64').toString('utf8');
    const blob = JSON.parse(json) as EncBlob;
    if (blob?.v !== 1 || blob?.alg !== 'A256GCM') throw new Error('Unsupported encrypted token blob.');
    const iv = b64ToBuf(blob.ivB64);
    const tag = b64ToBuf(blob.tagB64);
    const ct = b64ToBuf(blob.ctB64);
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString('utf8');
  }
}

