import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppConfigModule } from './config/config.module';
import { PrismaModule } from './prisma/prisma.module';
import { CryptoModule } from './crypto/crypto.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { IamModule } from './iam/iam.module';
import { SwaggerAuthMiddleware } from './iam/middleware/swagger-auth.middleware';
import { RequestIdMiddleware } from './iam/middleware/request-id.middleware';

@Module({
  imports: [
    AppConfigModule,
    PrismaModule,
    CryptoModule,
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 300 }]),
    IamModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(RequestIdMiddleware).forRoutes('*');
    consumer.apply(SwaggerAuthMiddleware).forRoutes('/docs', '/docs-json');
  }
}
