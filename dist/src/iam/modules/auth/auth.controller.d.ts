import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../../config/env.schema';
import { AuthService } from './auth.service';
export declare class AuthController {
    private readonly auth;
    private readonly config;
    constructor(auth: AuthService, config: ConfigService<Env, true>);
    login(res: Response): Promise<void>;
    callback(req: Request, res: Response, code?: string, state?: string): Promise<void | Response<any, Record<string, any>>>;
    logout(req: Request, res: Response): Promise<void>;
    me(req: Request): Promise<{
        authenticated: boolean;
        user?: undefined;
    } | {
        authenticated: boolean;
        user: import("./auth.types").AuthenticatedUser;
    }>;
}
