import { ConfigService } from '@nestjs/config';
import type { Env } from '../config/env.schema';
export declare class TokenCryptoService {
    private readonly config;
    private readonly key;
    constructor(config: ConfigService<Env, true>);
    encrypt(plain: string): string;
    decrypt(encB64: string): string;
}
