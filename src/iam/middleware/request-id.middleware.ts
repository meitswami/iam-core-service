import { Injectable } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'crypto';

declare module 'express-serve-static-core' {
  interface Request {
    requestId?: string;
  }
}

@Injectable()
export class RequestIdMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const existing = (req.get('x-request-id') ?? '').trim();
    const requestId = existing || randomUUID();
    req.requestId = requestId;
    res.setHeader('x-request-id', requestId);
    next();
  }
}

